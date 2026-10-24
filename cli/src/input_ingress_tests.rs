#[test]
fn whole_ingress_limit_and_empty_input_preserve_actual_allocation() {
    let budget = IngressBudget::with_limit(8);
    let first = budget.admit_owned(vec![1; 5]).unwrap();
    let bytes = vec![2; 4];
    let pointer = bytes.as_ptr();
    let rejected = budget.admit_owned(bytes).unwrap_err();
    assert_eq!(rejected.bytes.as_ptr(), pointer);
    assert_eq!(rejected.bytes, [2; 4]);
    assert_eq!(budget.usage(), (5, 1, 5));
    let empty = budget.admit_owned(Vec::with_capacity(1000)).unwrap();
    assert_eq!(budget.usage(), (5, 1, 5));
    assert!(empty.is_empty());
    drop((first, empty));
    assert_eq!(budget.usage(), (0, 0, 0));
}

#[test]
fn backing_capacity_is_bounded_independently_of_read_count() {
    let budget = IngressBudget::with_limit(8);
    let mut bytes = Vec::with_capacity(100);
    bytes.push(1);
    let pointer = bytes.as_ptr();
    let rejected = budget.admit_owned(bytes).unwrap_err();
    assert_eq!(rejected.bytes.as_ptr(), pointer);
    assert_eq!(rejected.bytes.capacity(), 100);
    let a = budget.admit_owned(vec![1]).unwrap();
    let b = budget.admit_owned(vec![2]).unwrap();
    assert!(budget.admit_slice(&[3; 7]).is_err());
    assert_eq!(budget.usage(), (2, 2, 2));
    drop((a, b));
    assert_eq!(budget.usage(), (0, 0, 0));
}

#[test]
fn derived_tail_retains_only_its_actual_unique_read_owners() {
    let budget = IngressBudget::with_limit(8);
    let mut a = budget.admit_owned(vec![1; 4]).unwrap();
    a.append(budget.admit_owned(vec![2; 4]).unwrap());
    let mut output = InputBuilder::default();
    output.original(&a, 2..8);
    let output = output.finish();
    assert_eq!(output.owner_count(), 2);
    let tail = output.copy_range(4..6);
    drop((a, output));
    assert_eq!(tail.as_slice(), [2; 2]);
    assert_eq!(tail.owner_count(), 1);
    assert_eq!(budget.usage(), (4, 1, 4));
    drop(tail);
    assert_eq!(budget.usage(), (0, 0, 0));
}

#[test]
fn duplicated_ranges_share_one_obligation_without_guard_amplification() {
    let budget = IngressBudget::with_limit(8);
    let input = budget.admit_owned(vec![1; 4]).unwrap();
    let mut builder = InputBuilder::default();
    builder.original(&input, 0..2);
    builder.original(&input, 2..4);
    builder.derived(b"mapped", &input, 0..4);
    let derived = builder.finish();
    drop(input);
    assert_eq!(derived.owner_count(), 1);
    assert_eq!(budget.usage(), (4, 1, 4));
    drop(derived);
    assert_eq!(budget.usage(), (0, 0, 0));
}

#[test]
fn continuous_suffix_replacement_does_not_accumulate_consumed_read_owners() {
    let budget = IngressBudget::with_limit(8);
    let mut tail = budget.admit_owned(vec![1; 4]).unwrap().copy_range(3..4);
    for byte in 2..100 {
        let next = budget.admit_owned(vec![byte; 4]).unwrap();
        tail.append(next);
        let new_tail = tail.copy_range(tail.len() - 1..tail.len());
        drop(tail);
        tail = new_tail;
        assert_eq!(tail.owner_count(), 1);
        assert_eq!(budget.usage(), (4, 1, 4));
    }
    drop(tail);
    assert_eq!(budget.usage(), (0, 0, 0));
}

#[test]
fn concurrent_ingress_reservation_is_whole_and_atomic() {
    use std::sync::Barrier;
    let budget = IngressBudget::with_limit(7);
    let barrier = Arc::new(Barrier::new(3));
    let hold = Arc::new(Barrier::new(3));
    let threads: Vec<_> = (0..2)
        .map(|_| {
            let (budget, barrier, hold) = (budget.clone(), barrier.clone(), hold.clone());
            std::thread::spawn(move || {
                barrier.wait();
                let input = budget.admit_slice(&[1; 4]);
                hold.wait();
                input
            })
        })
        .collect();
    barrier.wait();
    hold.wait();
    let inputs: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(inputs.iter().filter(|input| input.is_ok()).count(), 1);
    assert_eq!(budget.usage(), (4, 1, 4));
    drop(inputs);
    assert_eq!(budget.usage(), (0, 0, 0));
}

#[test]
fn recovery206_thousand_distinct_reads_are_byte_bounded_not_read_bounded() {
    let budget = IngressBudget::default();
    let mut bytes = InputBytes::default();
    for _ in 0..1000 {
        bytes.append(budget.admit_slice(b"x").expect("one byte fits"));
    }
    assert_eq!(bytes.owner_count(), 1000);
    assert_eq!(budget.usage(), (1000, 1000, 1000));
    drop(bytes);
    assert_eq!(budget.usage(), (0, 0, 0));
}

#[test]
fn recovery206_pending_lease_is_shared_with_emitted_action_until_final_alias_drop() {
    let budget = IngressBudget::default();
    let source = IngressBudget::default();
    let mut pending = PendingInput::default();
    pending
        .append(&source.admit_slice(b"abc").unwrap(), &budget)
        .unwrap();
    assert_eq!(source.usage(), (0, 0, 0));
    assert_eq!(budget.usage(), (INGRESS_BYTES, 1, INGRESS_BYTES));
    let input = pending.into_input().unwrap();
    assert_eq!(input.bytes.capacity(), INGRESS_BYTES);
    let alias = input.copy_range(1..3);
    drop(input);
    let mut next = PendingInput::default();
    assert!(next
        .append(&source.admit_slice(b"z").unwrap(), &budget)
        .is_err());
    drop(alias);
    next.append(&source.admit_slice(b"z").unwrap(), &budget)
        .unwrap();
    drop(next);
    assert_eq!(budget.usage(), (0, 0, 0));
}

#[test]
fn recovery206_pending_append_is_whole_and_never_grows_past_byte_capacity() {
    let budget = IngressBudget::default();
    let source = IngressBudget::default();
    let mut pending = PendingInput::default();
    pending
        .append(
            &source.admit_slice(&vec![b'x'; INGRESS_BYTES - 1]).unwrap(),
            &budget,
        )
        .unwrap();
    assert!(pending
        .append(&source.admit_slice(b"yz").unwrap(), &budget)
        .is_err());
    assert_eq!(pending.bytes.len(), INGRESS_BYTES - 1);
    assert_eq!(pending.bytes.capacity(), INGRESS_BYTES);
    pending
        .append(&source.admit_slice(b"z").unwrap(), &budget)
        .unwrap();
    assert_eq!(pending.bytes.len(), INGRESS_BYTES);
}

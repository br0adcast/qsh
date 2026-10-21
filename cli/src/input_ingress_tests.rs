#[test]
fn whole_ingress_limit_and_empty_input_preserve_actual_allocation() {
    let budget = IngressBudget::with_limits(8, 2);
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
fn backing_capacity_and_read_count_are_independent_limits() {
    let budget = IngressBudget::with_limits(8, 2);
    let mut bytes = Vec::with_capacity(100);
    bytes.push(1);
    let pointer = bytes.as_ptr();
    let rejected = budget.admit_owned(bytes).unwrap_err();
    assert_eq!(rejected.bytes.as_ptr(), pointer);
    assert_eq!(rejected.bytes.capacity(), 100);
    let a = budget.admit_owned(vec![1]).unwrap();
    let b = budget.admit_owned(vec![2]).unwrap();
    assert!(budget.admit_slice(&[3]).is_err());
    assert_eq!(budget.usage(), (2, 2, 2));
    drop((a, b));
    assert_eq!(budget.usage(), (0, 0, 0));
}

#[test]
fn derived_tail_retains_only_its_actual_unique_read_owners() {
    let budget = IngressBudget::with_limits(8, 2);
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
    let budget = IngressBudget::with_limits(8, 2);
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
    let budget = IngressBudget::with_limits(8, 2);
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
    let budget = IngressBudget::with_limits(7, 2);
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

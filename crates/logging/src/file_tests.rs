use super::*;

#[test]
fn rotation_bound_failed_reopen_does_not_grow_retained_inode_and_recovers() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.log");
    let held_path = dir.path().join("held.log");
    let sink = FileSink::open(&path, 100).unwrap();
    sink.write_lines(&["initial".into()]);
    let held = sink.try_clone_file().unwrap();
    let before = held.metadata().unwrap().len();
    fs::rename(&path, &held_path).unwrap();
    fs::create_dir(&path).unwrap(); // real reopen failure, including as root
    for _ in 0..100 {
        sink.write_lines(&["x".repeat(30)]);
    }
    let after_failure = held.metadata().unwrap().len();
    fs::remove_dir(&path).unwrap();
    sink.write_lines(&["recovered".into()]);
    let recovered = fs::read_to_string(&path).unwrap();
    assert_eq!(
        after_failure, before,
        "failed reopen must not append to the displaced inode (cap100)"
    );
    assert_eq!(held.metadata().unwrap().len(), before);
    assert_eq!(recovered, "recovered\n", "later write retries reopening");
}

#[test]
fn rotation_bound_failed_rename_drops_until_rotation_recovers() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.log");
    let rotated = dir.path().join("client.log.1");
    let sink = FileSink::open(&path, 100).unwrap();
    for _ in 0..3 {
        sink.write_lines(&["a".repeat(30)]);
    }
    let held = sink.try_clone_file().unwrap();
    fs::create_dir(&rotated).unwrap();
    for _ in 0..100 {
        sink.write_lines(&["b".repeat(30)]);
    }
    let failed_size = held.metadata().unwrap().len();
    fs::remove_dir(&rotated).unwrap();
    sink.write_lines(&["recovered".into()]);
    assert_eq!(
        failed_size, 93,
        "prospective append must not overrun the threshold"
    );
    assert_eq!(held.metadata().unwrap().len(), 93);
    assert_eq!(fs::metadata(rotated).unwrap().len(), 93);
    assert_eq!(fs::read_to_string(path).unwrap(), "recovered\n");
}

#[test]
fn rotation_bound_missing_or_replaced_parent_does_not_extend_old_file() {
    for replaced in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("logs");
        let moved = dir.path().join("held-logs");
        let path = parent.join("client.log");
        let sink = FileSink::open(&path, 100).unwrap();
        sink.write_lines(&["initial".into()]);
        let held = sink.try_clone_file().unwrap();
        fs::rename(&parent, &moved).unwrap();
        if replaced {
            fs::write(&parent, "owned blocker").unwrap();
        }
        for _ in 0..100 {
            sink.write_lines(&["x".repeat(30)]);
        }
        let failed_size = held.metadata().unwrap().len();
        if replaced {
            fs::remove_file(&parent).unwrap();
        }
        fs::rename(&moved, &parent).unwrap();
        sink.write_lines(&["recovered".into()]);
        assert_eq!(failed_size, 8, "replaced={replaced}");
        assert_eq!(fs::read_to_string(path).unwrap(), "initial\nrecovered\n");
    }
}

#[test]
fn rotation_bound_oversize_zero_and_exact_fit_preserve_whole_records() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.log");
    let rotated = dir.path().join("client.log.1");
    let sink = FileSink::open(&path, 8).unwrap();
    sink.write_lines(&["1234567".into()]); // exactly8 including newline
    sink.write_lines(&["12345678".into(), "x".repeat(1000)]);
    assert_eq!(fs::read_to_string(&path).unwrap(), "1234567\n");
    assert!(
        !rotated.exists(),
        "oversized records must not rotate useful logs"
    );
    sink.write_lines(&["ok".into()]);
    assert_eq!(fs::read_to_string(path).unwrap(), "ok\n");
    assert_eq!(fs::read_to_string(rotated).unwrap(), "1234567\n");
    let disabled_path = dir.path().join("disabled.log");
    let disabled = FileSink::open(&disabled_path, 0).unwrap();
    disabled.write_lines(&[String::new(), "record".into()]);
    assert_eq!(fs::metadata(disabled_path).unwrap().len(), 0);
    assert!(!dir.path().join("disabled.log.1").exists());
}

#[test]
fn rotation_bound_existing_oversize_file_is_not_truncated_or_extended_on_failure() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.log");
    let rotated = dir.path().join("client.log.1");
    let original = "existing\n".repeat(100);
    fs::write(&path, &original).unwrap();
    let sink = FileSink::open(&path, 100).unwrap();
    let held = sink.try_clone_file().unwrap();
    fs::create_dir(&rotated).unwrap();
    for _ in 0..100 {
        sink.write_lines(&["new record".into()]);
    }
    let failed_size = held.metadata().unwrap().len();
    fs::remove_dir(&rotated).unwrap();
    sink.write_lines(&["recovered".into()]);
    assert_eq!(failed_size, original.len() as u64);
    assert_eq!(fs::read_to_string(rotated).unwrap(), original);
    assert_eq!(fs::read_to_string(path).unwrap(), "recovered\n");
}

#[test]
fn rotation_bound_independent_writers_have_a_finite_race_bound_and_recover() {
    use std::sync::{mpsc, Arc};
    const WRITERS: usize = 3;
    const BOUND: u64 = 100;
    const LINE_BYTES: usize = 81;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.log");
    let rotated = dir.path().join("client.log.1");
    let (entered, arrivals) = mpsc::channel();
    let mut releases = Vec::new();
    let mut sinks = Vec::new();
    let mut workers = Vec::new();
    for index in 0..WRITERS {
        let sink = Arc::new(FileSink::open(&path, BOUND).unwrap());
        let (release, held) = mpsc::channel();
        sink.inner.lock().unwrap().before_append = Some((entered.clone(), held));
        releases.push(release);
        sinks.push(sink.clone());
        workers.push(std::thread::spawn(move || {
            let record = char::from(b'a' + index as u8)
                .to_string()
                .repeat(LINE_BYTES - 1);
            for _ in 0..100 {
                sink.write_lines(std::slice::from_ref(&record));
            }
        }));
    }
    drop(entered);
    fs::create_dir(&rotated).unwrap();
    let mut prepared = 0;
    for _ in 0..WRITERS {
        if arrivals
            .recv_timeout(std::time::Duration::from_secs(2))
            .is_ok()
        {
            prepared += 1;
        } else {
            break;
        }
    }
    // Every writer has passed actual descriptor preflight before any append.
    // Drop releases even on a missing arrival so no fixture thread is abandoned.
    drop(releases);
    let joined: Vec<_> = workers
        .into_iter()
        .map(std::thread::JoinHandle::join)
        .collect();
    assert!(
        joined.iter().all(Result::is_ok),
        "all owned writers must join"
    );
    let held = sinks[0].try_clone_file().unwrap();
    let raced_size = held.metadata().unwrap().len();
    let raced = fs::read_to_string(&path).unwrap();
    fs::remove_dir(&rotated).unwrap();
    for sink in &sinks {
        sink.write_lines(&["recovered".into()]);
    }
    assert_eq!(prepared, WRITERS, "actual preflight phases must all arrive");
    assert_eq!(raced_size, (WRITERS * LINE_BYTES) as u64);
    assert!(
        raced_size > BOUND,
        "independent preflights cannot promise a strict global cap"
    );
    assert!(raced_size <= BOUND + (WRITERS as u64 - 1) * LINE_BYTES as u64);
    let records: Vec<_> = raced.lines().collect();
    assert_eq!(records.len(), WRITERS);
    assert!(records
        .iter()
        .all(|line| line.len() == LINE_BYTES - 1 && line.bytes().all(|b| b == line.as_bytes()[0])));
    assert_eq!(held.metadata().unwrap().len(), raced_size);
    assert_eq!(
        fs::read_to_string(path).unwrap(),
        "recovered\n".repeat(WRITERS)
    );
}

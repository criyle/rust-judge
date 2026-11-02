use super::prelude::*;

pub(crate) fn worker_result_delivery(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Tokio benchmark runtime");
    runtime.block_on(async {
        // Warm the reusable blocking pool before Criterion starts sampling.
        tokio::task::spawn_blocking(|| {}).await.unwrap();
    });

    c.bench_function("worker/result_delivery_tokio_oneshot", |b| {
        b.iter(|| {
            runtime.block_on(async {
                let (sender, receiver) = tokio::sync::oneshot::channel();
                let producer = tokio::task::spawn_blocking(move || {
                    let _ = sender.send(black_box(1u8));
                });
                black_box(receiver.await.unwrap());
                producer.await.unwrap();
            });
        });
    });
    c.bench_function("worker/result_delivery_blocking_mpsc_ablation", |b| {
        b.iter(|| {
            runtime.block_on(async {
                let (sender, receiver) = mpsc::channel();
                let producer = tokio::task::spawn_blocking(move || {
                    let _ = sender.send(black_box(1u8));
                });
                let consumer = tokio::task::spawn_blocking(move || receiver.recv());
                black_box(consumer.await.unwrap().unwrap());
                producer.await.unwrap();
            });
        });
    });
}

pub(crate) fn profile_sampler_blocking_pool_availability(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .expect("Tokio benchmark runtime");
    let sample_window = std::time::Duration::from_millis(5);

    c.bench_function("runtime/profile_pool_probe_async_timer", |b| {
        b.iter_custom(|iterations| {
            let mut elapsed = std::time::Duration::ZERO;
            for _ in 0..iterations {
                elapsed += runtime.block_on(async {
                    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
                    let sampling = tokio::spawn(async move {
                        let _ = started_tx.send(());
                        tokio::time::sleep(sample_window).await;
                    });
                    started_rx.await.unwrap();
                    let started = Instant::now();
                    tokio::task::spawn_blocking(|| {}).await.unwrap();
                    let probe_elapsed = started.elapsed();
                    sampling.await.unwrap();
                    black_box(probe_elapsed)
                });
            }
            elapsed
        });
    });

    c.bench_function("runtime/profile_pool_probe_blocking_ablation", |b| {
        b.iter_custom(|iterations| {
            let mut elapsed = std::time::Duration::ZERO;
            for _ in 0..iterations {
                elapsed += runtime.block_on(async {
                    let (started_tx, started_rx) = mpsc::channel();
                    let sampling = tokio::task::spawn_blocking(move || {
                        let _ = started_tx.send(());
                        thread::sleep(sample_window);
                    });
                    started_rx.recv().unwrap();
                    let started = Instant::now();
                    tokio::task::spawn_blocking(|| {}).await.unwrap();
                    let probe_elapsed = started.elapsed();
                    sampling.await.unwrap();
                    black_box(probe_elapsed)
                });
            }
            elapsed
        });
    });
}

pub(crate) fn tokio_task_poll_hook_overhead(c: &mut Criterion) {
    let mut plain_builder = tokio::runtime::Builder::new_current_thread();
    plain_builder.enable_all();
    let plain_runtime = plain_builder
        .build()
        .expect("plain Tokio benchmark runtime");

    let mut hooks_only_builder = tokio::runtime::Builder::new_current_thread();
    hooks_only_builder.enable_all();
    rust_judge::runtime_trace::install_task_poll_hooks_without_schedule_latency(
        &mut hooks_only_builder,
    );
    let hooks_only_runtime = hooks_only_builder
        .build()
        .expect("Tokio hooks-only benchmark runtime");

    let mut schedule_latency_builder = tokio::runtime::Builder::new_current_thread();
    schedule_latency_builder.enable_all();
    rust_judge::runtime_trace::install_task_poll_hooks_with_schedule_latency(
        &mut schedule_latency_builder,
        true,
    );
    let schedule_latency_runtime = schedule_latency_builder
        .build()
        .expect("Tokio schedule-latency benchmark runtime");

    for (name, runtime) in [
        ("runtime/task_poll_hooks_disabled", &plain_runtime),
        (
            "runtime/task_poll_hooks_no_schedule_latency",
            &hooks_only_runtime,
        ),
        (
            "runtime/task_poll_hooks_with_schedule_latency",
            &schedule_latency_runtime,
        ),
    ] {
        c.bench_function(name, |b| {
            b.iter(|| {
                runtime.block_on(async {
                    let task = tokio::spawn(async {
                        tokio::task::yield_now().await;
                        black_box(1u8)
                    });
                    black_box(task.await.unwrap());
                });
            });
        });
    }
}

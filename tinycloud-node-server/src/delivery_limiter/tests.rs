use super::*;
use parking_lot::Mutex as TestMutex;

type Seen = Arc<TestMutex<Vec<Scope>>>;
type Observer = Arc<dyn Fn(Scope) + Send + Sync>;

/// The refusals the limiter reported, in order.
fn observed() -> (Seen, Observer) {
    let seen = Arc::new(TestMutex::new(Vec::new()));
    let sink = seen.clone();
    (seen, Arc::new(move |scope| sink.lock().push(scope)))
}

fn limiter(per_minute: u32, global: u32) -> (FetchLimiter, Arc<TestMutex<Vec<Scope>>>) {
    let (seen, observe) = observed();
    (
        FetchLimiter::with_observer(per_minute, global, observe),
        seen,
    )
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

#[test]
fn an_invoker_is_refused_after_its_burst_and_another_invoker_is_not() {
    let (limiter, seen) = limiter(20, 90);
    let t0 = Instant::now();
    for _ in 0..5 {
        assert_eq!(limiter.check("invoker-a", t0), Ok(()));
    }
    // The sixth is refused: one token every three seconds.
    assert_eq!(
        limiter.check("invoker-a", t0),
        Err(Refused {
            scope: Scope::Invoker,
            retry_after_secs: 3
        })
    );
    assert_eq!(limiter.check("invoker-b", t0), Ok(()));
    assert_eq!(*seen.lock(), vec![Scope::Invoker]);

    // Refilled at the configured rate: nothing after 2 s, one token after 3 s.
    assert!(limiter
        .check("invoker-a", t0 + Duration::from_millis(2_900))
        .is_err());
    assert_eq!(
        limiter.check("invoker-a", t0 + Duration::from_millis(3_100)),
        Ok(())
    );
    assert!(limiter
        .check("invoker-a", t0 + Duration::from_millis(3_200))
        .is_err());
}

#[test]
fn the_bucket_refills_after_a_minute_to_the_burst_and_no_further() {
    let (limiter, _) = limiter(20, 90);
    let t0 = Instant::now();
    for _ in 0..5 {
        limiter.check("invoker-a", t0).unwrap();
    }
    assert!(limiter.check("invoker-a", t0).is_err());
    // A minute refills twenty tokens' worth; the bucket holds five.
    let later = t0 + secs(60);
    for _ in 0..5 {
        assert_eq!(limiter.check("invoker-a", later), Ok(()));
    }
    assert!(limiter.check("invoker-a", later).is_err());
}

#[test]
fn the_node_wide_cap_trips_for_many_invokers_and_frees_after_a_minute() {
    let (limiter, seen) = limiter(20, 90);
    let t0 = Instant::now();
    for n in 0..90 {
        assert_eq!(limiter.check(&format!("invoker-{n}"), t0), Ok(()), "{n}");
    }
    // The 91st fetch in the window, from a new invoker, is refused node-wide.
    assert_eq!(
        limiter.check("invoker-91", t0),
        Err(Refused {
            scope: Scope::Global,
            retry_after_secs: 60
        })
    );
    assert_eq!(*seen.lock(), vec![Scope::Global]);
    // Later in the window the wait shrinks.
    assert_eq!(
        limiter.check("invoker-91", t0 + secs(45)),
        Err(Refused {
            scope: Scope::Global,
            retry_after_secs: 15
        })
    );
    // The refusal consumed nothing from the invoker: after the window it has
    // its whole burst.
    let later = t0 + secs(61);
    for _ in 0..5 {
        assert_eq!(limiter.check("invoker-91", later), Ok(()));
    }
    assert!(limiter.check("invoker-91", later).is_err());
}

#[test]
fn a_refused_invoker_costs_the_node_wide_cap_nothing() {
    let (limiter, _) = limiter(20, 90);
    let t0 = Instant::now();
    for _ in 0..5 {
        limiter.check("noisy", t0).unwrap();
    }
    for _ in 0..200 {
        assert!(limiter.check("noisy", t0).is_err());
    }
    // Five fetches were admitted; the other 85 of the 90 are still free.
    for n in 0..85 {
        assert_eq!(limiter.check(&format!("other-{n}"), t0), Ok(()), "{n}");
    }
    assert_eq!(
        limiter.check("other-85", t0).unwrap_err().scope,
        Scope::Global
    );
}

#[test]
fn every_refusal_is_observed_once_with_its_scope() {
    let (limiter, seen) = limiter(20, 90);
    let t0 = Instant::now();
    for _ in 0..5 {
        limiter.check("a", t0).unwrap();
    }
    for _ in 0..3 {
        assert!(limiter.check("a", t0).is_err());
    }
    // Fill the node-wide cap with other invokers, then two more refusals.
    for n in 0..85 {
        limiter.check(&format!("o-{n}"), t0).unwrap();
    }
    for n in 0..2 {
        assert_eq!(
            limiter.check(&format!("late-{n}"), t0).unwrap_err().scope,
            Scope::Global
        );
    }
    assert_eq!(
        *seen.lock(),
        vec![
            Scope::Invoker,
            Scope::Invoker,
            Scope::Invoker,
            Scope::Global,
            Scope::Global
        ]
    );
    assert_eq!(
        limiter.take_refusals(),
        vec![(Scope::Invoker, 3), (Scope::Global, 2)]
    );
    assert!(limiter.take_refusals().is_empty());
}

#[test]
fn the_registered_counter_has_the_two_scopes_and_nothing_else() {
    use crate::prometheus::DELIVERY_RATE_LIMITED;
    let before = |scope| DELIVERY_RATE_LIMITED.with_label_values(&[scope]).get();
    // The counter is process-wide and other tests refuse too, so it is only
    // required to have grown.
    let invoker = before("invoker");
    // The production limiter increments the registered counter.
    let limiter = FetchLimiter::new(20, 90);
    let t0 = Instant::now();
    for _ in 0..5 {
        limiter.check("counter-test", t0).unwrap();
    }
    assert!(limiter.check("counter-test", t0).is_err());
    assert!(before("invoker") > invoker);
    for scope in [Scope::Invoker, Scope::Global] {
        let label = scope.as_str();
        assert!(matches!(label, "invoker" | "global"));
        assert!(!label.contains(':') && !label.contains('/') && !label.contains(' '));
    }
}

#[test]
fn the_set_of_tracked_invokers_is_bounded() {
    let (limiter, _) = limiter(20, 90);
    limiter.set_limits(20, 5, 1_000_000);
    let t0 = Instant::now();
    for n in 0..MAX_TRACKED_INVOKERS {
        limiter.check(&format!("i-{n}"), t0).unwrap();
    }
    assert_eq!(limiter.tracked_invokers(), MAX_TRACKED_INVOKERS);
    // Not idle yet: a new invoker is not tracked and only the node-wide cap
    // applies to it.
    for _ in 0..50 {
        assert_eq!(limiter.check("newcomer", t0), Ok(()));
    }
    assert_eq!(limiter.tracked_invokers(), MAX_TRACKED_INVOKERS);
    // A tracked invoker is still limited.
    for _ in 0..4 {
        limiter.check("i-0", t0).unwrap();
    }
    assert!(limiter.check("i-0", t0).is_err());
    // Once the tracked ones are idle (full again) they are dropped to make
    // room, and the newcomer is tracked.
    let later = t0 + secs(600);
    limiter.check("newcomer", later).unwrap();
    assert_eq!(limiter.tracked_invokers(), 1);
}

#[test]
fn the_configured_limits_are_checked_when_the_configuration_loads() {
    assert_eq!(validate_limits(20, 90), Ok(()));
    assert_eq!(validate_limits(1, 1), Ok(()));
    assert_eq!(validate_limits(20, 110), Ok(()));
    assert!(validate_limits(0, 90).is_err());
    assert!(validate_limits(20, 0).is_err());
    assert!(validate_limits(20, 111).is_err());
    assert!(validate_limits(0, 0).is_err());

    use crate::config::ShareEmailConfig;
    let defaults = ShareEmailConfig::default();
    assert_eq!(defaults.links_fetch_per_invoker_per_minute, 20);
    assert_eq!(defaults.links_fetch_global_per_minute, 90);
    assert!(defaults.validate_links_fetch_limits().is_ok());
    let from_toml: ShareEmailConfig = serde_json::from_value(serde_json::json!({
        "links_fetch_per_invoker_per_minute": 7,
        "links_fetch_global_per_minute": 30,
    }))
    .unwrap();
    assert_eq!(from_toml.links_fetch_per_invoker_per_minute, 7);
    assert_eq!(from_toml.links_fetch_global_per_minute, 30);

    let mut config = crate::config::Config::default();
    assert!(crate::resolve_runtime_config(&config).is_ok());
    for (per_invoker, global) in [(0, 90), (20, 0), (20, 111), (20, 1_000_000)] {
        config.share_email.links_fetch_per_invoker_per_minute = per_invoker;
        config.share_email.links_fetch_global_per_minute = global;
        assert!(
            crate::resolve_runtime_config(&config).is_err(),
            "{per_invoker} {global}"
        );
    }
}

/// Everything logged on this thread while a test runs, as JSON lines.
#[derive(Clone, Default)]
struct Captured(Arc<TestMutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Captured;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn lines(captured: &Captured) -> Vec<serde_json::Value> {
    String::from_utf8(captured.0.lock().clone())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

/// `#[tokio::test]` runs on one thread, so the thread-scoped subscriber sees
/// the report task; time is paused and advanced by hand.
#[tokio::test(start_paused = true)]
async fn one_aggregated_line_per_scope_per_minute_and_none_without_refusals() {
    const INVOKER: &str = "did:key:zSENTINELINVOKERDID";
    const LINK: &str = "https://share.tinycloud.xyz/s/lqdw5iopqq2tkkvjj6gbbi5vbv#v=4&k=SENTINELKEY";
    let captured = Captured::default();
    let _subscriber = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .json()
            .with_writer(captured.clone())
            .with_max_level(tracing::Level::WARN)
            .finish(),
    );
    let (limiter, _) = limiter(20, 90);
    let limiter = Arc::new(limiter);
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(run_report(limiter.clone(), async move {
        let _ = stopped.await;
    }));
    // The task creates its interval when it first runs; let it, before time moves.
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    let minute = async {
        tokio::time::advance(secs(60)).await;
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
    };

    // Minute one: many refusals of both scopes, one line each.
    let t0 = Instant::now();
    for _ in 0..5 {
        limiter.check(INVOKER, t0).unwrap();
    }
    for _ in 0..40 {
        assert!(limiter.check(INVOKER, t0).is_err());
    }
    for n in 0..85 {
        limiter.check(&format!("{INVOKER}-{n}"), t0).unwrap();
    }
    for n in 0..7 {
        assert!(limiter.check(&format!("{LINK}-{n}"), t0).is_err());
    }
    assert!(lines(&captured).is_empty(), "nothing is logged per refusal");
    minute.await;
    let first = lines(&captured);
    assert_eq!(first.len(), 2, "{first:?}");
    let by_scope = |scope: &str| {
        first
            .iter()
            .find(|line| line["fields"]["scope"] == scope)
            .unwrap_or_else(|| panic!("no line for {scope}"))
    };
    assert_eq!(by_scope("invoker")["fields"]["count"], 40);
    assert_eq!(by_scope("global")["fields"]["count"], 7);
    for line in &first {
        assert_eq!(line["level"], "WARN");
        assert_eq!(line["fields"]["event"], "delivery_rate_limited");
        assert_eq!(line["fields"]["window_s"], 60);
        let mut keys: Vec<_> = line["fields"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        keys.sort();
        assert_eq!(keys, ["count", "event", "message", "scope", "window_s"]);
    }

    // Minute two: no refusals, no line.
    tokio::time::advance(secs(60)).await;
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    assert_eq!(lines(&captured).len(), 2);

    // Minute three: one refusal, one line with count 1.
    let t3 = Instant::now() + secs(1000);
    for _ in 0..5 {
        limiter.check("late", t3).unwrap();
    }
    assert!(limiter.check("late", t3).is_err());
    tokio::time::advance(secs(60)).await;
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    let all = lines(&captured);
    assert_eq!(all.len(), 3, "{all:?}");
    assert_eq!(all[2]["fields"]["count"], 1);
    assert_eq!(all[2]["fields"]["scope"], "invoker");

    // The sentinel: no invoker, link, key or address in any line.
    let text = String::from_utf8(captured.0.lock().clone()).unwrap();
    for secret in ["SENTINEL", "did:key", "#v=4", "share.tinycloud", "@"] {
        assert!(!text.contains(secret), "{secret} in {text}");
    }

    let _ = stop.send(());
    task.await.unwrap();
}

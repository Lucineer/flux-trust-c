# flux-trust-c 🛡️

**C11 Bayesian trust scoring for embedded agent fleets.** Same trust model as [flux-trust](https://github.com/Lucineer/flux-trust) (Rust), designed for bare-metal deployment on ESP32, Jetson, or CUDA kernels.

```c
TrustTable tt;
TrustConfig cfg = { .none_threshold = 0.2, .trusted_threshold = 0.6,
                    .max_trust = 0.95, .positive_weight = 0.1,
                    .negative_weight = 0.3, .decay_per_hour = 0.01 };

trust_init(&tt);
trust_observe(&tt, 7, 1, &cfg, now);  // positive observation
printf("Agent 7 trust: %.2f\n", trust_score(&tt, 7));
printf("Trusted: %s\n", trust_is_trusted(&tt, 7, &cfg) ? "yes" : "no");
```

## API

```c
// Initialize a trust table (128 agents max)
TrustTable tt;
trust_init(&tt);

// Record an observation (+1 positive, 0 = negative)
trust_observe(&tt, agent_id, /* positive: */ 1, &cfg, now);

// Query trust score (returns -1 if agent unknown)
float score = trust_score(&tt, agent_id);

// Decay trust over time (call periodically)
trust_decay(&tt, now, /* hours elapsed: */ 24);

// Hard revoke
trust_revoke(&tt, agent_id, "exfiltrated credentials");
int revoked = trust_is_revoked(&tt, agent_id);  // 1

// Unrevoke
trust_unrevoke(&tt, agent_id);

// Social queries
int trusted = trust_is_trusted(&tt, agent_id, &cfg);
TrustEntry top5[5];
trust_most_trusted(&tt, 5, top5);   // sort by score
trust_least_trusted(&tt, 5, top5);  // sort by score
int n_trusted = trust_count_trusted(&tt, &cfg);

// Direct access
TrustEntry* e = trust_find(&tt, agent_id);
if (e) printf("Score: %.2f, obs: %u\n", e->score, e->observations);
```

## Lifetime Model

```
birth (0.5) → observations adjust → decay weakens → death < none_threshold
                          ↘ revoked → permanent exclusion ←
```

- **Positive weight (0.1)**: slow trust building
- **Negative weight (0.3)**: 3× faster distrust (betrayal hurts more)
- **Decay (0.01/hr)**: trust erodes ~0.24/day if unmaintained
- **Max trust (0.95)**: never 100% — always room for doubt

## Build & Test

```bash
make test
```

## Why C11?

- **Embedded targets** — ESP32, STM32, bare-metal ARM
- **CUDA integration** — compile with `nvcc` for GPU trust scoring
- **Zero deps** — no libc required beyond stdint/string, fits in 3KB binary
- **Deterministic** — no allocation, no float surprises

## Fleet Context

Part of the Lucineer/Cocapn fleet. C11 sibling to [flux-trust](https://github.com/Lucineer/flux-trust) (Rust), paired with [flux-confidence](https://github.com/Lucineer/flux-confidence) for calibrated self-awareness.

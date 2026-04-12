#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "trust.h"

static int tests_run = 0;
static int tests_passed = 0;

#define FLOAT_EQ(a,b) ((a)-(b)>-1e-6f && (a)-(b)<1e-6f)
#define ASSERT(cond, msg) do { \
    tests_run++; \
    if (cond) { tests_passed++; } \
    else { fprintf(stderr, "FAIL [%d]: %s\n", tests_run, msg); } \
} while(0)

static TrustConfig default_cfg(void) {
    TrustConfig c = {0};
    c.none_threshold = 0.2f;
    c.trusted_threshold = 0.6f;
    c.max_trust = 0.95f;
    c.positive_weight = 0.1f;
    c.negative_weight = 0.3f;
    c.decay_per_hour = 0.01f;
    return c;
}

int main(void) {
    TrustTable tt;
    TrustConfig cfg = default_cfg();
    TrustEntry buf[TRUST_ENTRIES_MAX];

    // 1. init empty
    trust_init(&tt);
    ASSERT(tt.count == 0, "init empty");

    // 2. get_or_create
    TrustEntry *e = trust_get_or_create(&tt, 1, 100);
    ASSERT(e != NULL, "get_or_create returns non-null");
    ASSERT(e->agent_id == 1, "get_or_create sets agent_id");
    ASSERT(e->score == 0.5f, "get_or_create default score 0.5");
    ASSERT(tt.count == 1, "get_or_create increments count");

    // 3. find unknown returns null
    ASSERT(trust_find(&tt, 99) == NULL, "find unknown returns null");

    // 4. observe positive increases
    trust_init(&tt);
    e = trust_get_or_create(&tt, 1, 100);
    float before = e->score;
    trust_observe(&tt, 1, 1, &cfg, 101);
    ASSERT(e->score > before, "observe positive increases score");
    ASSERT(e->positive == 1, "positive count incremented");

    // 5. observe negative decreases
    trust_init(&tt);
    trust_get_or_create(&tt, 1, 100);
    before = tt.entries[0].score;
    trust_observe(&tt, 1, 0, &cfg, 101);
    ASSERT(tt.entries[0].score < before, "observe negative decreases score");
    ASSERT(tt.entries[0].negative == 1, "negative count incremented");

    // 6. observe respects weights
    trust_init(&tt);
    trust_get_or_create(&tt, 1, 100);
    trust_observe(&tt, 1, 1, &cfg, 101);
    float after_pos = tt.entries[0].score;
    ASSERT(FLOAT_EQ(after_pos - 0.5f, cfg.positive_weight), "positive weight respected");

    // 7. observe clamps to max
    trust_init(&tt);
    trust_get_or_create(&tt, 1, 100);
    for (int i = 0; i < 100; i++)
        trust_observe(&tt, 1, 1, &cfg, 100 + i);
    ASSERT(tt.entries[0].score <= cfg.max_trust + 0.0001f, "score clamped to max_trust");

    // 8. observe clamps to zero
    trust_init(&tt);
    trust_get_or_create(&tt, 1, 100);
    for (int i = 0; i < 100; i++)
        trust_observe(&tt, 1, 0, &cfg, 100 + i);
    ASSERT(tt.entries[0].score >= 0.0f - 0.0001f, "score clamped to zero");

    // 9. decay reduces score
    trust_init(&tt);
    trust_get_or_create(&tt, 1, 100);
    trust_observe(&tt, 1, 1, &cfg, 101);
    before = tt.entries[0].score;
    trust_decay(&tt, 200, 1);
    ASSERT(tt.entries[0].score < before, "decay reduces score");

    // 10. revoke sets flag
    trust_init(&tt);
    trust_get_or_create(&tt, 1, 100);
    trust_revoke(&tt, 1, "malicious");
    ASSERT(tt.entries[0].revoked == 1, "revoke sets flag");
    ASSERT(strcmp(tt.entries[0].revoke_reason, "malicious") == 0, "revoke reason set");

    // 11. revoked returns -1
    ASSERT(trust_score(&tt, 1) == -1.0f, "revoked returns -1 score");
    ASSERT(trust_is_revoked(&tt, 1) == 1, "is_revoked returns 1");

    // 12. unrevoke clears
    trust_unrevoke(&tt, 1);
    ASSERT(tt.entries[0].revoked == 0, "unrevoke clears flag");
    ASSERT(trust_score(&tt, 1) != -1.0f, "unrevoked score not -1");

    // 13. is_trusted respects threshold
    trust_init(&tt);
    trust_get_or_create(&tt, 1, 100);
    ASSERT(trust_is_trusted(&tt, 1, &cfg) == 0, "score 0.5 not trusted");
    // boost above threshold
    for (int i = 0; i < 5; i++)
        trust_observe(&tt, 1, 1, &cfg, 101 + i);
    ASSERT(trust_is_trusted(&tt, 1, &cfg) == 1, "score >= 0.6 is trusted");

    // 14. most_trusted sorted
    trust_init(&tt);
    trust_get_or_create(&tt, 1, 100);
    trust_get_or_create(&tt, 2, 100);
    trust_get_or_create(&tt, 3, 100);
    trust_observe(&tt, 3, 1, &cfg, 101);
    trust_observe(&tt, 3, 1, &cfg, 102);
    trust_observe(&tt, 2, 1, &cfg, 101);
    int n = 3;
    trust_most_trusted(&tt, n, buf);
    ASSERT(buf[0].agent_id == 3, "most_trusted first is agent 3");
    ASSERT(buf[1].agent_id == 2, "most_trusted second is agent 2");
    ASSERT(buf[2].agent_id == 1, "most_trusted third is agent 1");

    // 15. least_trusted sorted
    trust_least_trusted(&tt, n, buf);
    ASSERT(buf[0].agent_id == 1, "least_trusted first is agent 1");
    ASSERT(buf[2].agent_id == 3, "least_trusted last is agent 3");

    // 16. count_trusted
    int ct = trust_count_trusted(&tt, &cfg);
    ASSERT(ct == 2, "count_trusted after boosting");
    // make all trusted
    for (int i = 0; i < (int)tt.count; i++)
        for (int j = 0; j < 10; j++)
            trust_observe(&tt, tt.entries[i].agent_id, 1, &cfg, 200 + j);
    ct = trust_count_trusted(&tt, &cfg);
    ASSERT(ct == 3, "count_trusted after boosting all");

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}

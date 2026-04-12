#ifndef TRUST_H
#define TRUST_H

#include <stdint.h>
#include <stddef.h>

#define TRUST_ENTRIES_MAX 128

typedef struct {
    uint16_t agent_id;
    float score;           // 0.0-1.0
    uint32_t observations; // total interactions
    uint32_t positive;
    uint32_t negative;
    uint64_t last_seen;    // epoch
    uint64_t created;
    float max_trust;       // peak trust achieved
    float decay_rate;      // per-hour decay
    uint8_t revoked;       // hard revoke
    char revoke_reason[64];
} TrustEntry;

typedef struct {
    TrustEntry entries[TRUST_ENTRIES_MAX];
    uint16_t count;
} TrustTable;

typedef struct {
    float none_threshold;     // below this = untrusted, default 0.2
    float trusted_threshold;  // above this = trusted, default 0.6
    float max_trust;          // hard cap, default 0.95
    float positive_weight;    // weight for positive obs, default 0.1
    float negative_weight;    // weight for negative obs, default 0.3
    float decay_per_hour;     // trust decay rate, default 0.01
} TrustConfig;

// API
void trust_init(TrustTable *tt);
TrustEntry* trust_get_or_create(TrustTable *tt, uint16_t agent_id, uint64_t now);
TrustEntry* trust_find(TrustTable *tt, uint16_t agent_id);
float trust_score(TrustTable *tt, uint16_t agent_id);  // returns -1 if unknown
void trust_observe(TrustTable *tt, uint16_t agent_id, int positive, const TrustConfig *cfg, uint64_t now);
void trust_decay(TrustTable *tt, uint64_t now, uint64_t elapsed_hours);
void trust_revoke(TrustTable *tt, uint16_t agent_id, const char *reason);
void trust_unrevoke(TrustTable *tt, uint16_t agent_id);
int trust_is_trusted(TrustTable *tt, uint16_t agent_id, const TrustConfig *cfg);
int trust_is_revoked(TrustTable *tt, uint16_t agent_id);
TrustEntry* trust_most_trusted(TrustTable *tt, int n, TrustEntry *results);
TrustEntry* trust_least_trusted(TrustTable *tt, int n, TrustEntry *results);
int trust_count_trusted(TrustTable *tt, const TrustConfig *cfg);

#endif

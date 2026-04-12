#include <stdio.h>
#include "trust.h"
#include <math.h>
#include <string.h>

void trust_init(TrustTable *tt) {
    memset(tt, 0, sizeof(*tt));
}

TrustEntry* trust_find(TrustTable *tt, uint16_t agent_id) {
    for (uint16_t i = 0; i < tt->count; i++) {
        if (tt->entries[i].agent_id == agent_id)
            return &tt->entries[i];
    }
    return NULL;
}

TrustEntry* trust_get_or_create(TrustTable *tt, uint16_t agent_id, uint64_t now) {
    TrustEntry *e = trust_find(tt, agent_id);
    if (e) return e;
    if (tt->count >= TRUST_ENTRIES_MAX) return NULL;
    e = &tt->entries[tt->count++];
    memset(e, 0, sizeof(*e));
    e->agent_id = agent_id;
    e->score = 0.5f;
    e->created = now;
    e->last_seen = now;
    e->max_trust = 0.5f;
    e->decay_rate = 0.01f;
    return e;
}

float trust_score(TrustTable *tt, uint16_t agent_id) {
    TrustEntry *e = trust_find(tt, agent_id);
    if (!e) return -1.0f;
    if (e->revoked) return -1.0f;
    return e->score;
}

void trust_observe(TrustTable *tt, uint16_t agent_id, int positive, const TrustConfig *cfg, uint64_t now) {
    TrustEntry *e = trust_find(tt, agent_id);
    if (!e) e = trust_get_or_create(tt, agent_id, now);
    if (!e) return;
    e->observations++;
    if (positive) {
        e->positive++;
        e->score += cfg->positive_weight;
    } else {
        e->negative++;
        e->score -= cfg->negative_weight;
    }
    if (e->score > cfg->max_trust) e->score = cfg->max_trust;
    if (e->score < 0.0f) e->score = 0.0f;
    if (e->score > e->max_trust) e->max_trust = e->score;
    e->last_seen = now;
}

void trust_decay(TrustTable *tt, uint64_t now, uint64_t elapsed_hours) {
    for (uint16_t i = 0; i < tt->count; i++) {
        TrustEntry *e = &tt->entries[i];
        if (e->revoked) continue;
        float decay = 1.0f - e->decay_rate;
        for (uint64_t h = 0; h < elapsed_hours; h++)
            e->score *= decay;
        if (e->score < 0.0f) e->score = 0.0f;
        e->last_seen = now;
    }
}

void trust_revoke(TrustTable *tt, uint16_t agent_id, const char *reason) {
    TrustEntry *e = trust_find(tt, agent_id);
    if (!e) return;
    e->revoked = 1;
    if (reason) {
        size_t len = strlen(reason);
        if (len >= sizeof(e->revoke_reason)) len = sizeof(e->revoke_reason) - 1;
        memcpy(e->revoke_reason, reason, len);
        e->revoke_reason[len] = '\0';
    } else {
        e->revoke_reason[0] = '\0';
    }
}

void trust_unrevoke(TrustTable *tt, uint16_t agent_id) {
    TrustEntry *e = trust_find(tt, agent_id);
    if (!e) return;
    e->revoked = 0;
    e->revoke_reason[0] = '\0';
}

int trust_is_trusted(TrustTable *tt, uint16_t agent_id, const TrustConfig *cfg) {
    TrustEntry *e = trust_find(tt, agent_id);
    if (!e) return 0;
    if (e->revoked) return 0;
    return e->score >= cfg->trusted_threshold;
}

int trust_is_revoked(TrustTable *tt, uint16_t agent_id) {
    TrustEntry *e = trust_find(tt, agent_id);
    if (!e) return 0;
    return e->revoked;
}

// Insertion-sort helper: insert entry into sorted results, return new count
static int insert_trusted(TrustEntry *results, int count, const TrustEntry *e, int reverse) {
    int pos = count;
    for (int i = 0; i < count; i++) {
        float cmp = (e->revoked ? -1.0f : e->score) - (results[i].revoked ? -1.0f : results[i].score);
        if (reverse) cmp = -cmp;
        if (cmp > 0.0f || (cmp >= 0.0f && e->agent_id < results[i].agent_id)) {
            pos = i;
            break;
        }
    }
    for (int i = count; i > pos; i--)
        results[i] = results[i - 1];
    results[pos] = *e;
    return count + 1;
}

TrustEntry* trust_most_trusted(TrustTable *tt, int n, TrustEntry *results) {
    int count = 0;
    for (uint16_t i = 0; i < tt->count; i++)
        count = insert_trusted(results, count, &tt->entries[i], 0);
    if (count < n) n = count;
    return results; // caller gets first n
}

TrustEntry* trust_least_trusted(TrustTable *tt, int n, TrustEntry *results) {
    int count = 0;
    for (uint16_t i = 0; i < tt->count; i++)
        count = insert_trusted(results, count, &tt->entries[i], 1);
    if (count < n) n = count;
    return results;
}

int trust_count_trusted(TrustTable *tt, const TrustConfig *cfg) {
    int count = 0;
    for (uint16_t i = 0; i < tt->count; i++) {
        TrustEntry *e = &tt->entries[i];
        if (!e->revoked && e->score >= cfg->trusted_threshold)
            count++;
    }
    return count;
}

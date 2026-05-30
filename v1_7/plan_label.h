// SPDX-License-Identifier: MIT
/*
 * plan_label.h — VAREK v1.7 flat-set taint / capability labels.
 *
 * A label is an opaque tag id in [0, PLAN_MAX_LABELS). A label set
 * is a fixed-capacity bitset. Forward propagation along plan edges
 * is modeled as set union: a successor receives the union of its
 * predecessors' outbound sets. v1.7.0 is a flat set — no partial
 * order over labels and no declassification primitive. Both are
 * deferred to a later v1.7.x.
 *
 * The type is allocation-free: a set is a small inline array of
 * 64-bit words, so it composes with the v1.6 fixed-capacity,
 * no-dynamic-allocation discipline.
 */

#ifndef VAREK_V1_7_PLAN_LABEL_H
#define VAREK_V1_7_PLAN_LABEL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Number of distinct labels. Must be a positive multiple of 64. */
#ifndef PLAN_MAX_LABELS
#define PLAN_MAX_LABELS 128u
#endif

#define PLAN_LABEL_WORDS (PLAN_MAX_LABELS / 64u)

/* Reserved sentinel for "no label". */
#define PLAN_LABEL_INVALID UINT16_MAX

typedef uint16_t plan_label_t;

typedef struct {
    uint64_t bits[PLAN_LABEL_WORDS];
} plan_label_set_t;

/* PLAN_MAX_LABELS must tile cleanly into 64-bit words, and a label
 * id must be representable in plan_label_t with room for the
 * sentinel. Enforced at compile time. */
#if (PLAN_MAX_LABELS % 64u) != 0u
#error "PLAN_MAX_LABELS must be a multiple of 64"
#endif
#if PLAN_MAX_LABELS >= UINT16_MAX
#error "PLAN_MAX_LABELS must fit in plan_label_t below the sentinel"
#endif

static inline bool plan_label_valid(plan_label_t t)
{
    return t < PLAN_MAX_LABELS;
}

static inline void plan_label_set_clear(plan_label_set_t *s)
{
    for (size_t i = 0; i < PLAN_LABEL_WORDS; i++)
        s->bits[i] = 0;
}

/* Returns 0 on success, -1 if the tag is out of range. */
static inline int plan_label_set_add(plan_label_set_t *s, plan_label_t t)
{
    if (!plan_label_valid(t))
        return -1;
    s->bits[t >> 6] |= ((uint64_t)1) << (t & 63u);
    return 0;
}

static inline bool plan_label_set_test(const plan_label_set_t *s,
                                       plan_label_t t)
{
    if (!plan_label_valid(t))
        return false;
    return (bool)((s->bits[t >> 6] >> (t & 63u)) & 1u);
}

/* dst <- dst U src */
static inline void plan_label_set_union_into(plan_label_set_t *dst,
                                             const plan_label_set_t *src)
{
    for (size_t i = 0; i < PLAN_LABEL_WORDS; i++)
        dst->bits[i] |= src->bits[i];
}

/* dst <- a ∩ b. Used for the declassification audit set
 * (inbound ∩ declassify). v1.8.0. */
static inline void plan_label_set_intersect_into(plan_label_set_t *dst,
                                                 const plan_label_set_t *a,
                                                 const plan_label_set_t *b)
{
    for (size_t i = 0; i < PLAN_LABEL_WORDS; i++)
        dst->bits[i] = a->bits[i] & b->bits[i];
}

/* dst <- dst \ sub  (remove from dst every label present in sub).
 * Used for declassification: a node strips its declassify set from
 * the labels it propagates onward. v1.8.0. */
static inline void plan_label_set_minus_into(plan_label_set_t *dst,
                                             const plan_label_set_t *sub)
{
    for (size_t i = 0; i < PLAN_LABEL_WORDS; i++)
        dst->bits[i] &= ~sub->bits[i];
}

/* True iff (a & b) is non-empty. */
static inline bool plan_label_set_intersects(const plan_label_set_t *a,
                                             const plan_label_set_t *b)
{
    for (size_t i = 0; i < PLAN_LABEL_WORDS; i++)
        if (a->bits[i] & b->bits[i])
            return true;
    return false;
}

static inline bool plan_label_set_empty(const plan_label_set_t *s)
{
    for (size_t i = 0; i < PLAN_LABEL_WORDS; i++)
        if (s->bits[i])
            return false;
    return true;
}

/* True iff (a ∩ ~b) is non-empty — equivalently, 'a contains a label
 * that b does not'. Used for the sticky-unclassified check. */
static inline bool plan_label_set_minus_nonempty(const plan_label_set_t *a,
                                                 const plan_label_set_t *b)
{
    for (size_t i = 0; i < PLAN_LABEL_WORDS; i++)
        if (a->bits[i] & ~b->bits[i])
            return true;
    return false;
}

#ifdef __cplusplus
}
#endif

#endif /* VAREK_V1_7_PLAN_LABEL_H */

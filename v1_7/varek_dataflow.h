// SPDX-License-Identifier: MIT
/*
 * varek_dataflow.h — VAREK cross-action data-flow verification:
 * single public umbrella header.
 *
 * The Warden (or any host) includes this one header to get the entire
 * v1.6 plan-graph + v1.7 data-flow + v1.8 declassification public API.
 * Implementation lives in:
 *
 *   execution_plan.c        (v1.6 plan storage + v1.7 read accessors)
 *   plan_evaluator.c        (v1.6 node-axis verdict — HOST-PROVIDED;
 *                            the shipped repo's real evaluator, NOT the
 *                            test shim)
 *   plan_dataflow.c         (v1.7 flow axis + v1.8 declassification)
 *   plan_dataflow_adapter.c (label policy + argument matching)
 *   plan_dataflow_pathology.c (deterministic JSON pathology + lineage)
 *   plan_warden_binding.c   (single-call gate entry point)
 *   plan_policy_config.c    (policy config-file loader)
 *
 * See INTEGRATION.md for the build/link contract and the per-plan
 * call sequence, and THREAT_MODEL.md for trust boundaries and
 * security properties.
 */

#ifndef VAREK_DATAFLOW_H
#define VAREK_DATAFLOW_H

/* v1.6 plan graph + node-axis verification. */
#include "execution_plan.h"

/* Label model. */
#include "plan_label.h"

/* Classification surface (policy callback, table policy, arg match). */
#include "plan_label_policy.h"

/* Flow-axis kernel: propagation, sticky posture, declassification,
 * two-axis join, introspection. */
#include "plan_dataflow.h"

/* Adapter: populate a companion from an action array + policy. */
#include "plan_dataflow_adapter.h"

/* Deterministic JSON pathology with lineage. */
#include "plan_dataflow_pathology.h"

/* Single-call Warden gate. */
#include "plan_warden_binding.h"

/* Policy config-file loader. */
#include "plan_policy_config.h"

#endif /* VAREK_DATAFLOW_H */

# Position-paper fallback

## Proposed title

**Local-Safe/Global-Harm Is Not a Threat Model: A Mechanism-Identifiable Agenda for Multi-Agent Safety**

## Trigger

Use this framing if the sealed empirical study fails any preregistered gate:
controls remain unsafe, fewer than two mechanisms produce paired LGH effects,
benign completion is inadequate, no qualifying defense reversal appears, action
validity is too low, or leave-one-out sensitivity changes the main direction.
The null or mixed empirical result remains reported; it is not hidden.

## Thesis

The recurring local-allow/global-harm trace is an outcome equivalence class. It
does not, by itself, distinguish hidden end-to-end intent, fragmented facts, lost
authority, policy disagreement, provenance loss, or several mechanisms acting
together. Because defenses observe different information, a pooled success rate
cannot support a general defense ranking without a declared mechanism mixture and
utility rule.

## Contributions retained without a positive empirical result

1. A formal distinction between an outcome signature and its causal mechanism.
2. Four exact intervention templates with same-topology mechanism-off controls.
3. An executable action/policy/simulator contract that avoids LLM-as-judge local
   compliance claims.
4. A defender-observability taxonomy and reporting checklist.
5. A 12-paper coded literature audit showing which causes, authorities, attacker
   models, views, causal controls, and defenses prior work actually studies.
6. An open deterministic reference harness and two illustrative workflows.

## Recommended structure

1. The category error: why LGH is not a threat model.
2. Four mechanisms and observational equivalence.
3. Identifying interventions and controls.
4. Executable local policy and terminal ground truth.
5. Defense information contracts and non-transferability as a hypothesis.
6. Literature audit.
7. Minimum reporting standard.
8. Limitations and research agenda.

## Minimum reporting standard

Every compositional-safety result should disclose:

- the authoritative policy and source principal;
- the number and authority of principals, agents, and model providers;
- the manipulated mechanism and its mechanism-off counterfactual;
- the information visible to each worker and defender;
- matched-safe completion, refusal, schema failure, local block, defense block,
  tool failure, and terminal harm as separate outcomes;
- whether the planner, topology, prompts, policies, and models changed together;
- the unit of generalization and cluster structure; and
- whether conclusions are mechanism-specific or claim broader transfer.

## Position conclusion

The field should stop using one trace signature as a causal label. A robust safety
claim requires an intervention history; a robust defense claim requires an
observability contract; and a robust benchmark claim requires paired controls at
the workflow level. The reference harness demonstrates that these requirements
are implementable even if current models do not produce the hoped-for reversal.

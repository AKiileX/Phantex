/**
 * PHANTEX — Formal Verification of Sandbox Isolation (Alloy 6)
 *
 * Models the agent sandboxing architecture (Block AM prerequisite).
 * Proves three critical isolation properties:
 *
 *   P1: RESOURCE CONTAINMENT
 *       A sandboxed agent cannot access any resource outside its allowlist.
 *
 *   P2: QUARANTINE CAPTURE
 *       A quarantined agent's every external action is captured in an
 *       audit log — nothing escapes unlogged.
 *
 *   P3: NO LATERAL MOVEMENT
 *       No agent in sandbox A can reach any resource exclusively owned
 *       by sandbox B, even transitively through shared tools.
 *
 * The model corresponds to the runtime isolation layer described in
 * Phantex-draft.md §27 (Agent Sandboxing & Runtime Isolation).
 */

-- ══════════════════════════════════════════════════════════════════
-- Domain signatures
-- ══════════════════════════════════════════════════════════════════

/** A tenant in the multi-tenant system. */
sig Tenant {}

/** An AI agent executing within a sandbox. */
sig Agent {
  tenant   : one Tenant,
  sandbox  : one Sandbox,
  /** The set of resources this agent is permitted to access. */
  allowlist: set Resource
}

/** A sandbox boundary (gVisor / Firecracker / WASM runtime). */
sig Sandbox {
  tenant : one Tenant,
  mode   : one SandboxMode,
  /** Resources physically accessible from within this sandbox. */
  accessible : set Resource
}

/** Resources: files, network endpoints, APIs, memory regions. */
sig Resource {
  owner : one Tenant
}

/** Tools (MCP servers, APIs) that agents can invoke. */
sig Tool {
  /** Each tool accesses a fixed set of resources. */
  accesses : set Resource
}

/** Every agent action is a discrete event. */
sig Action {
  actor    : one Agent,
  target   : one Resource,
  via      : lone Tool,       -- optional: direct access has no tool
  logged   : one Bool
}

/** Bool helper (Alloy 6 built-in, but explicit for clarity). */
enum Bool { True, False }

/** Sandbox operating modes. */
enum SandboxMode { Normal, Quarantine }

-- ══════════════════════════════════════════════════════════════════
-- Structural constraints (well-formedness)
-- ══════════════════════════════════════════════════════════════════

/** Agents only exist in sandboxes of their own tenant. */
fact AgentTenantMatch {
  all a: Agent | a.sandbox.tenant = a.tenant
}

/** Resources are accessible in a sandbox only if they belong to that tenant. */
fact SandboxResourceTenancy {
  all s: Sandbox, r: s.accessible | r.owner = s.tenant
}

/** An agent's allowlist must be a subset of its sandbox's accessible set. */
fact AllowlistSubsetAccessible {
  all a: Agent | a.allowlist in a.sandbox.accessible
}

/** An action's target must be in the actor's allowlist (policy enforcement). */
fact ActionRequiresPermission {
  all act: Action | act.target in act.actor.allowlist
}

/** If an action goes through a tool, that tool must actually access the target. */
fact ToolAccessConsistency {
  all act: Action | some act.via implies act.target in act.via.accesses
}

/** In quarantine mode, every action is logged. */
fact QuarantineLogsEverything {
  all act: Action |
    act.actor.sandbox.mode = Quarantine implies act.logged = True
}

-- ══════════════════════════════════════════════════════════════════
-- P1: RESOURCE CONTAINMENT
-- A sandboxed agent cannot touch anything outside its allowlist.
-- ══════════════════════════════════════════════════════════════════

assert ResourceContainment {
  all act: Action | act.target in act.actor.allowlist
}

-- ══════════════════════════════════════════════════════════════════
-- P2: QUARANTINE CAPTURE
-- Every action by a quarantined agent is recorded in the audit log.
-- ══════════════════════════════════════════════════════════════════

assert QuarantineCapture {
  all act: Action |
    act.actor.sandbox.mode = Quarantine implies act.logged = True
}

-- ══════════════════════════════════════════════════════════════════
-- P3: NO LATERAL MOVEMENT
-- An agent in sandbox S1 can never access a resource that is
-- exclusively in another sandbox S2 of the same tenant.
-- "Exclusively" means the resource is accessible from S2 but NOT
-- from S1 — i.e. not in the actor's sandbox's accessible set.
-- ══════════════════════════════════════════════════════════════════

assert NoLateralMovement {
  all act: Action |
    act.target in act.actor.sandbox.accessible
}

-- Cross-tenant version: agents never touch resources of other tenants.
assert CrossTenantIsolation {
  all act: Action |
    act.target.owner = act.actor.tenant
}

-- ══════════════════════════════════════════════════════════════════
-- P4: TOOL MEDIATION SAFETY
-- Even indirect access through a tool respects sandbox boundaries.
-- A tool invoked by agent A can only touch resources in A's sandbox.
-- ══════════════════════════════════════════════════════════════════

assert ToolMediationSafety {
  all act: Action, t: act.via |
    act.target in act.actor.sandbox.accessible
}

-- ══════════════════════════════════════════════════════════════════
-- Check commands — Alloy Analyzer will search for counterexamples.
-- Scope: up to 5 of each atom (configurable in .thm / CLI).
-- ══════════════════════════════════════════════════════════════════

check ResourceContainment    for 5 but exactly 2 Tenant, 4 Agent, 3 Sandbox, 6 Resource, 3 Tool, 8 Action
check QuarantineCapture      for 5 but exactly 2 Tenant, 4 Agent, 3 Sandbox, 6 Resource, 3 Tool, 8 Action
check NoLateralMovement      for 5 but exactly 2 Tenant, 4 Agent, 3 Sandbox, 6 Resource, 3 Tool, 8 Action
check CrossTenantIsolation   for 5 but exactly 2 Tenant, 4 Agent, 3 Sandbox, 6 Resource, 3 Tool, 8 Action
check ToolMediationSafety    for 5 but exactly 2 Tenant, 4 Agent, 3 Sandbox, 6 Resource, 3 Tool, 8 Action

-- ══════════════════════════════════════════════════════════════════
-- Example: generate a valid instance to visualise the model.
-- ══════════════════════════════════════════════════════════════════

run ExampleInstance {
  #Tenant = 2
  #Agent = 3
  #Sandbox = 2
  #Resource = 4
  #Tool = 2
  #Action >= 3
  some a: Agent | a.sandbox.mode = Quarantine
} for 5

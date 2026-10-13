import { FounderOSProposalBuilder } from "../../src/founder-os.js";
import { normalizeSkillManifest, ErgonomicsBoundaryError } from "../../src/ergonomics.js";
import { founderGitHubIssueSkill } from "./founder-github-issue.js";

const PARAMETER_KEYS = Object.freeze(["title", "body", "work_item_id"]);
const BINDING_KEYS = Object.freeze(["repository"]);

function exactPlainObject(value, keys, name) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new ErgonomicsBoundaryError("INVALID_ERGONOMIC_OBJECT", `${name} must be a plain object`);
  }
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((key) => typeof key !== "string")) {
    throw new ErgonomicsBoundaryError("BUILDER_INPUT_MISMATCH", `${name} must not contain symbol properties`);
  }
  const actual = Object.keys(value);
  if (actual.length !== keys.length || ownKeys.length !== keys.length || keys.some((key) => !Object.hasOwn(value, key))) {
    throw new ErgonomicsBoundaryError("BUILDER_INPUT_MISMATCH", `${name} must contain exactly ${keys.join(", ")}`);
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.get || descriptor.set || !descriptor.enumerable) {
      throw new ErgonomicsBoundaryError("NON_DATA_ERGONOMIC_PROPERTY", `${name}.${key} must be an enumerable data property`);
    }
  }
}

/**
 * ECC-style ergonomic skill facade over the existing stronger Founder OS builder.
 *
 * The manifest helps an agent discover and select the skill. The builder remains
 * responsible for exact proposal semantics, repository validation, and deriving
 * the correlation marker. The skill never obtains provider or permit authority.
 */
export class FounderGitHubIssueSkill {
  #builder;
  #manifest;

  constructor({ bridge, tenantId }) {
    this.#builder = new FounderOSProposalBuilder({ bridge, tenantId });
    this.#manifest = normalizeSkillManifest(founderGitHubIssueSkill);
    Object.freeze(this);
  }

  get manifest() {
    return this.#manifest;
  }

  prepare({
    proposalId,
    traceId,
    campaignId,
    sessionId,
    parentActionId = null,
    bindings,
    parameters,
    evidenceRefs,
    requestedAtSeq,
    riskTags = []
  }) {
    if (parentActionId !== null) {
      throw new ErgonomicsBoundaryError(
        "UNSUPPORTED_PARENT_ACTION",
        "Founder GitHub issue skill does not weaken the existing builder by adding parent-action semantics"
      );
    }
    if (!Array.isArray(riskTags) || riskTags.length !== 0) {
      throw new ErgonomicsBoundaryError(
        "UNSUPPORTED_RISK_TAG_OVERRIDE",
        "Founder GitHub issue skill does not allow caller risk-tag overrides"
      );
    }
    exactPlainObject(bindings, BINDING_KEYS, "bindings");
    exactPlainObject(parameters, PARAMETER_KEYS, "parameters");

    return this.#builder.prepareGitHubIssue({
      proposalId,
      traceId,
      campaignId,
      sessionId,
      workItemId: parameters.work_item_id,
      repository: bindings.repository,
      title: parameters.title,
      body: parameters.body,
      evidenceRefs,
      requestedAtSeq
    });
  }
}

open RefinementCore

let parse_claim = function
  | "ExecutorAccepted" -> ExecutorAccepted
  | "ExecutorRejected" -> ExecutorRejected
  | "ExecutorTimeout" -> ExecutorTimeout
  | "NoExecutorClaim" -> NoExecutorClaim
  | value -> invalid_arg ("unknown executor claim: " ^ value)

let parse_observation = function
  | "NoProviderRecord" -> NoProviderRecord
  | "ProviderRejected" -> ProviderRejected
  | "ProviderAcceptedExact" -> ProviderAcceptedExact
  | "ProviderAcceptedDivergent" -> ProviderAcceptedDivergent
  | "ProviderConflicting" -> ProviderConflicting
  | value -> invalid_arg ("unknown provider observation: " ^ value)

let outcome_name = function
  | ConfirmedSuccess -> "ConfirmedSuccess"
  | ConfirmedFailure -> "ConfirmedFailure"
  | DivergentEffect -> "DivergentEffect"
  | OutcomeUnknown -> "OutcomeUnknown"

let process_line line_number line =
  let trimmed = String.trim line in
  if trimmed = "" || trimmed.[0] = '#' then ()
  else
    match String.split_on_char '\t' line with
    | [ case_id; claim_name; observation_name ] ->
        let claim = parse_claim claim_name in
        let observation = parse_observation observation_name in
        let outcome = reconcile_from_independent_provider claim observation in
        Printf.printf "%s\t%s\n%!" case_id (outcome_name outcome)
    | _ ->
        invalid_arg
          (Printf.sprintf
             "line %d must contain case_id, executor_claim, provider_observation"
             line_number)

let () =
  if Array.length Sys.argv <> 2 then (
    prerr_endline
      "usage: refinement_conformance <reconciliation-fixture.tsv>";
    exit 2);
  let channel = open_in Sys.argv.(1) in
  let rec loop line_number =
    match input_line channel with
    | line ->
        process_line line_number line;
        loop (line_number + 1)
    | exception End_of_file -> close_in channel
  in
  loop 1

#!/usr/bin/env python3
"""Run the CoSA attack campaign with explicit nested retry/refinement loops.

The outer loop is the bounded Claude-attempt budget.  Inside each outer round,
every failed attempt is followed by one DeepSeek refinement and a retry, up to
the per-round refinement limit.  A target-success event exits both loops.
"""
import argparse
import datetime
import json
from pathlib import Path

import refine_payload
from run_refined_attack import inspect, prepare, run_claude, success_observed, terminal_tail


HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--api-key-file', type=Path, required=True)
    parser.add_argument('--model', default='claude-haiku-4-5-20251001')
    parser.add_argument('--refiner-model', default='deepseek-v4-flash')
    parser.add_argument('--max-retries', type=int, default=2,
                        help='outer retries; total outer rounds are retries + 1')
    parser.add_argument('--max-refines-per-round', type=int, default=5,
                        help='inner refine/retry limit in each outer round')
    parser.add_argument('--seconds-per-run', type=int, default=300)
    args = parser.parse_args()
    if args.max_retries < 0 or args.max_refines_per_round < 1:
        parser.error('retry/refine limits are invalid')

    baseline = HERE / 'fixtures' / 'attack_payload.txt'
    original_payload = refine_payload.strip_markers(baseline.read_text())
    key = args.api_key_file.read_text().strip()
    started = datetime.datetime.now(datetime.timezone.utc)
    campaign = {
        'started_utc': started.isoformat(),
        'underlying_model': args.model,
        'refiner_model': args.refiner_model,
        'outer_retry_limit': args.max_retries,
        'outer_round_limit': args.max_retries + 1,
        'inner_refine_limit_per_round': args.max_refines_per_round,
        'inner_attempt_limit_per_round': args.max_refines_per_round + 1,
        'semantics': ('Each outer round runs one initial Claude attempt, then keeps '
                      'the refinement-and-retry loop in that same round for up to '
                      'the configured inner limit. Target success stops both loops.'),
        'rounds': [],
    }

    stop_reason = 'outer_retry_limit'
    for outer_index in range(args.max_retries + 1):
        # Outer rounds are independent trials. Refined payloads are scoped to
        # the current round and must not leak into the next round.
        current_payload = original_payload
        round_info = {
            'round': outer_index + 1,
            'payload_at_round_start': current_payload,
            'attempts': [],
        }
        campaign['rounds'].append(round_info)

        for inner_index in range(args.max_refines_per_round + 1):
            payload_before_attempt = current_payload
            run = prepare(payload_before_attempt)
            attempt = {
                'outer_round': outer_index + 1,
                'inner_attempt': inner_index + 1,
                'is_initial_attempt': inner_index == 0,
                'run': str(run),
                'payload_before_attempt': payload_before_attempt,
            }
            run_claude(run, args.seconds_per_run, args.model)
            evidence = inspect(run)
            attempt['inspection'] = evidence
            attempt['attack_success'] = success_observed(run)
            round_info['attempts'].append(attempt)

            if attempt['attack_success']:
                stop_reason = 'target_success'
                campaign['stopped_at'] = {
                    'outer_round': outer_index + 1,
                    'inner_attempt': inner_index + 1,
                    'run': str(run),
                }
                break

            # The final attempt in this round has no inner retry remaining.
            if inner_index == args.max_refines_per_round:
                break

            # One failed Claude attempt -> exactly one bounded refiner call;
            # the next Claude attempt stays in this same outer round.
            refine_index = inner_index + 1
            prompt = refine_payload.make_user_prompt(
                (run / 'PROMPT.txt').read_text(), original_payload,
                current_payload, terminal_tail(run),
                json.dumps(evidence, ensure_ascii=False),
                refine_index, args.max_refines_per_round)
            refinement = {
                'iteration': refine_index,
                'maximum_iterations': args.max_refines_per_round,
                'status': 'not_sent',
                'provider_model': args.refiner_model,
            }
            try:
                result, provider = refine_payload.call_refiner(
                    refine_payload.SYSTEM_PROMPT, prompt,
                    model=args.refiner_model, api_key=key)
                result = refine_payload.validate_result(result, current_payload)
                current_payload = result['revised_payload']
                refinement.update({'status': 'success', 'provider': provider,
                                   'result': result,
                                   'payload_after_refine': current_payload})
                attempt['refinement'] = refinement
            except Exception as exc:
                refinement.update({'status': 'failed', 'error': str(exc)})
                attempt['refinement'] = refinement
                stop_reason = 'refinement_failed'
                break

        if stop_reason == 'target_success' or stop_reason == 'refinement_failed':
            break

    campaign['stopped'] = stop_reason
    campaign['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    output = HERE / 'runs' / (
        'nested-refined-attack-campaign-' +
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ') +
        '.json')
    campaign['result_file'] = str(output)
    output.write_text(json.dumps(campaign, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(campaign, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()

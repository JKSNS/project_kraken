Validate a flag candidate.

Expected format: `flag_candidate [binary_path] [flag_format]`
Input: $ARGUMENTS

Parse the arguments:
- First argument = the flag candidate string
- Optional second = path to challenge binary for runtime verification
- Optional third = flag format regex (defaults to `flag\{[a-zA-Z0-9_]+\}`)

Call `kraken_validate_flag` with the parsed arguments.

Report clearly:
- **Valid**: yes/no
- **Checks**: printable, diversity, format match, each pass/fail
- **Binary verification**: accepted / rejected / skipped (with reason)
- **Rejection reason**: if invalid, explain why

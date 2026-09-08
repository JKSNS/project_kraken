Decompile the challenge at: $ARGUMENTS

1. Call `kraken_triage` first to detect the binary type.
2. Call `kraken_decompile` with the challenge path.
3. Call `kraken_extract_params` with the decompiled functions, strings, and binary info.

Then give me a detailed analysis:
- Show the key functions (main, check/verify functions, crypto functions)
- Explain the validation logic, what does the binary check?
- List the extracted parameters: input mode, expected length, success string, key constants
- Identify the algorithm: XOR, substitution, strcmp, symbolic constraints, crypto, etc.
- Suggest a solve approach based on what you see

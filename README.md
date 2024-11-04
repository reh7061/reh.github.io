# Program Reverse Engineering Notes (Example)
# Made by ChatGPT

## Program Name/Hash
- **Type**: Crackme / Malware / CTF
- **Difficulty**: Medium
- **Tools Used**: IDA Pro, Ghidra, x64dbg, etc.

## Program Details
- **Description**: Short description of the program.
- **Objective**: Example: "Find the correct serial key" or "Analyze the malware’s behavior."

## Tools & Techniques
- **Debugger**: x64dbg for dynamic analysis.
- **Disassembler**: Ghidra for static analysis.

## Approach
1. **Step 1: Static Analysis**
   - Look for strings in the binary using `strings` command.
   - Check for common function calls (e.g., `strcmp` for crackmes).
   - Decompile the binary to identify function flow.

    ```c
    // Pseudo code
    if (strcmp(input, "correct_key") == 0) {
        printf("Access granted");
    }
    ```

2. **Step 2: Dynamic Analysis**
   - Set breakpoints on key functions like `strcmp` to trace execution.

## Key Findings
- **Anti-debug techniques**: Found checks for debuggers using `IsDebuggerPresent()`.
- **Obfuscation**: XOR-based obfuscation was used on strings.

## Solution
- **Patch**: Changed `jne` to `je` at address `0x40100` to bypass key check.
- **Keygen**: Wrote a small script in Python to generate valid serials.

    ```python
    # Python script to keygen
    def generate_key():
        return "correct_key"
    ```

## Challenges
- Example: Identifying and bypassing the anti-debugging checks.

## References
- [Relevant Blog Post](https://example.com)
- [Documentation for Ghidra](https://ghidra-sre.org)


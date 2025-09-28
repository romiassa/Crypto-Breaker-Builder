# Crypto Breaker & Builder 
## What’s It About?
 Crypto Breaker & Builder, a Python tool that plays the offensive hacker role by cracking weak ciphers like Caesar, Reverse, Atbash, Vigenère, and Substitution to turn codes like “KHOOR” into “HELLO” without knowing the cipher, and letting you encrypt messages to test attack techniques, all in a safe lab-only , built to show how attackers exploit outdated encryption in stuff like IoT or old apps while proving AES is better .

## Features
- **Crack Ciphers**: Drop a coded message; we test all five ciphers and pick the best plaintext.
- **Build Ciphers**: Choose a cipher (like Caesar with shift 3 or Vigenère with “SPY”) to craft your own encrypted message.
- **Smart Scoring**: Blends wordlist (“HELLO,” “SPY”) and English letter frequencies (E=12.7%, T=9%)—60% wordlist, 40% frequency—for cracking.
- **Easy Menu**: Crack or build ciphers, see results fast.

## How It Works
1. **Enter Message** (~50 lines): Type a coded message (e.g., “KHOOR”) or one to encrypt. We check it’s only letters and spaces.
2. **Five Ciphers**: Crack or build with Caesar (shift), Reverse (flip), Atbash (A→Z), Vigenère (keyword), and Substitution (mapping). Each has decrypt and encrypt functions.
3. **Auto-Decrypt Logic** (~100-150 lines): For cracking, try all five ciphers on the input (e.g., “KHOOR”), score outputs to find the right plaintext (e.g., “HELLO”):
   - **Brute-Force**: Caesar tries shifts 0-25; Reverse and Atbash need one try; Vigenère tests keys like “SPY” or “KEY”; Substitution maps frequent letters to E.
   - **Scoring**: Check against a wordlist (“HELLO,” “ATTACK,” “SPY”) for English-likeness and use frequency analysis (`collections.Counter`, E=12.7%, T=9%). Combine scores (60% wordlist, 40% frequency), sort, and pick the top candidate.
4. **Menu**: Choose to enter a message, crack it, or build one, and see results.

## Usage

**Start, pick:
- **Crack: Type “KHOOR,” get “HELLO” (Caesar, shift=3).
- ** Encrypt: Choose a cipher, encode your message.
** Example:
   ```bash
  Input: KHOOR
  Output: HELLO (Caesar, shift=3 )

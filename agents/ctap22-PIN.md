# PIN normative audit (§6.5)

- Persist retry reset before replacing live state. Failed writes must not make
  the in-memory retry budget less restrictive.
- Three consecutive failures require a power cycle. The previous implementation
  only returned PIN_AUTH_BLOCKED on the third failure, but continued accepting
  guesses afterward, including the correct PIN. Reject all such attempts until
  restart; persistent exhaustion still takes precedence and requires reset.
- Regressions cover three-attempt blocking, correct-PIN rejection while blocked,
  recovery after restart, persistent exhaustion, and failed store writes.

Next integration work: remove false built-in-UV behavior, verify wire types and
errors, version/protocol compatibility, and ensure PIN storage satisfies §6.5.1's
security requirement. A PBKDF2 verifier in a readable SQLite file is not a claim
of TPM-equivalent PIN storage protection. Do not label full conformance achieved
while that requirement or mandatory advertised-version features remain open.

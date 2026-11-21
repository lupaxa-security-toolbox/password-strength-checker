<p align="center">
  <a href="https://github.com/lupaxa-security-toolbox">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/organisations/security-toolbox/readme-logo.png" alt="Security Toolbox" />
  </a>
</p>

<h1 align="center">Password Strength Checker</h1>

Password Strength Checker scores a password with zxcvbn and can ask Have I Been Pwned whether that password has appeared in a known breach. The breach check is optional, so the tool also runs entirely offline.

The password is never a command-line argument and is never written to a report field. Have I Been Pwned receives only the first five characters of its SHA-1 hash.
The JSON report's pattern list can still contain pieces of the password, so treat that document as sensitive and do not log it.

## Install

Python 3.11 or newer:

```bash
pip install lupaxa-password-strength-checker
```

The command is `password-strength-checker`. The import path is `lupaxa.password_strength`. `lupaxa` is a namespace package — there is no `lupaxa/__init__.py`. zxcvbn is the only dependency. The breach check uses the Python standard library.

## Quick Start

Prompt for a password and stay offline:

```bash
password-strength-checker
```

Check Have I Been Pwned, and print JSON:

```bash
password-strength-checker --check-breach
password-strength-checker --json --check-breach
```

Tell zxcvbn about a username or organisation so those words count as predictable:

```bash
password-strength-checker --check-breach --user-input exampleuser --user-input examplecompany
```

The command asks for the password without echoing it. When standard input is not a terminal, it reads one line from stdin instead:

```bash
printf '%s\n' 'correct horse battery staple' | password-strength-checker --json
```

Library callers pass the password to `analyse`:

```python
from pathlib import Path

from lupaxa.password_strength import BannedList, BreachClient, Policy, analyse

report = analyse(
    password,
    user_inputs=["exampleuser"],
    breach_client=BreachClient(),
    banned_hashes=BannedList.read(Path("hashes.txt")),
    policy=Policy(min_score=75, reject_breached=True),
)
print(report.to_json())
```

Omit `breach_client` to stay offline. Omit `banned_hashes` and `policy` when you only want the assessment.

## Command Line Options

The password is not an option. It is prompted, or read as one line from stdin.

| Option                  | Meaning                                                                                                                                      | Example                                                  |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| `--help`, `-h`          | Print the command summary and exit.                                                                                                          | `password-strength-checker --help`                       |
| `--version`             | Print the version and exit.                                                                                                                  | `password-strength-checker --version`                    |
| `--check-breach`        | Ask Have I Been Pwned using k-anonymity. Off unless you pass this flag.                                                                      | `password-strength-checker --check-breach`               |
| `--json`                | Print one JSON document instead of the text card.                                                                                            | `password-strength-checker --json`                       |
| `--user-input WORD`     | A word zxcvbn should treat as predictable, such as a username or organisation. Repeat the option for each word.                              | `--user-input exampleuser --user-input examplecompany`   |
| `--timeout SECONDS`     | Seconds to wait for Have I Been Pwned. The number must be greater than zero. The default is 10.                                              | `--timeout 5`                                            |
| `--min-score N`         | Reject the password when the overall score is below this integer. `N` is from 0 to 100. A password that was not scored is rejected.          | `--min-score 75`                                         |
| `--reject-breached`     | Reject a breach or banned-list hit, and a check that did not finish. Requires `--check-breach` or `--banned-hashes`.                         | `--check-breach --reject-breached`                       |
| `--banned-hashes FILE`  | Local file of SHA-1 hashes, one per line. A hit sets the rating to Compromised. A missing or malformed file stays unknown.                   | `--banned-hashes hashes.txt`                             |

## What it Does

- Scores the password from 0 to 100 and gives it a rating.
- Keeps the original zxcvbn score, from 0 to 4.
- Estimates online and offline cracking time.
- Counts character classes and how many distinct characters were used.
- Keeps the pieces zxcvbn matched in the JSON report, including the matched text.
- Reports the estimated guess count and `log2` of that count.
- Optionally reports how many times Have I Been Pwned has seen the password.
- Returns zxcvbn's warning and suggestions.
- Reports characters that look like a different letter or digit, without changing the score.
- Can reject a password that misses a minimum score or shows up in a breach or banned list.
- Prints a summary card, or one JSON document.

The command exits 0 when a report was produced and any policy passed. It exits 3 when a policy rejects the password, 2 for a usage error, and 1 when analysis fails.

## Score

The overall score stays tied to zxcvbn. A confirmed breach or a banned-list hit forces the overall score to 0 and the rating to Compromised. The zxcvbn score is left unchanged so it can still be inspected.

| zxcvbn score         | Overall score | Rating       |
| -------------------- | ------------- | ------------ |
| 0                    | 0             | Very weak    |
| 1                    | 25            | Weak         |
| 2                    | 50            | Fair         |
| 3                    | 75            | Strong       |
| 4                    | 100           | Very strong  |
| Breach or banned hit | 0             | Compromised  |

`entropy_bits` is `log2` of the estimated guess count, rounded to two decimal places. It describes guessing difficulty. It is not the entropy of the process that created the password.

zxcvbn does not estimate guesses for a password longer than 72 characters. The report still includes the length and the character counts, `scored` is false, and `estimate_note` says why the guess fields were left empty.
The score is then null and the rating is Not scored, unless a breach or banned-list hit forces Compromised.

## Lookalikes

Some letters are not the ASCII letter they resemble. Cyrillic `а` is an example, and so is a fullwidth `Ａ`. The report lists each distinct character and the ASCII letter or digit it looks like.
Accented letters such as `é` are not treated as lookalikes. The finding does not change the score.

## Banned Hashes

`--banned-hashes FILE` checks a local list of SHA-1 hashes. Put one 40-character hash on each line. Blank lines and `#` comments are ignored, and a `HASH:COUNT` line is accepted. The password is hashed on this machine and compared locally.

```text
# organisation list
0123456789abcdef0123456789abcdef01234567
0123456789abcdef0123456789abcdef01234567:3
```

A hit sets the score to 0 and the rating to Compromised. A missing, unreadable, or malformed file leaves `banned` unset and does not call the password safe.
The file is meant for an organisation's own list. The full Have I Been Pwned corpus stays a range lookup.

## Policy

A policy is separate from the score. Omit it and the report is only an assessment.

```bash
password-strength-checker --check-breach --min-score 75 --reject-breached
password-strength-checker --banned-hashes hashes.txt --reject-breached
```

`--min-score` rejects an overall score below that number, from 0 to 100. A password that was not scored is rejected. `--reject-breached` needs `--check-breach` or `--banned-hashes`.
It rejects a confirmed hit, and it also rejects a check that did not complete. A completed check that did not find the password passes this rule. That result still does not mean the password is safe.

A breached password scores 0, so a minimum of 0 does not reject it. Use `--reject-breached` for that.

When no policy is set, the JSON field `policy` is null. Otherwise it is an object:

```json
{"accepted": false, "failures": ["score 25 is below 75", "found in a breach"]}
```

## Cracking Estimates

zxcvbn models four attackers. These are assumptions, not promised cracking times. The rates come from zxcvbn's original threat model.
A current high-end GPU, or a rented cluster, is faster than the fast-hash rate. The online throttled rate is still about the server's limit, not the attacker's computer.
Whether the slow-hash rate is high or low depends on the hash and its cost settings, which this tool cannot see.
`guesses` ages better than the clock times: it is how far down zxcvbn's ordered list the password sits. Each time below is that count divided by the rate in the table.

| Scenario             | Assumed guessing rate         |
| -------------------- | ----------------------------- |
| Online (Throttled)   | 100 guesses an hour           |
| Online (Unthrottled) | 10 guesses a second           |
| Offline (Slow Hash)  | 10,000 guesses a second       |
| Offline (Fast Hash)  | 10 billion guesses a second   |

## Breach Check

The check is off unless you pass `--check-breach` or a `BreachClient`.

1. The password is hashed locally with SHA-1.
2. The hash is split into a 5-character prefix and a 35-character suffix.
3. Only the prefix is sent to the Have I Been Pwned range API.
4. The response is padded. The suffix is compared on this machine.

The service sees the hash prefix and the request's network metadata. It does not see the password or the full hash.

| Status             | Meaning                                                         |
| ------------------ | --------------------------------------------------------------- |
| `not_checked`      | The breach check was not requested                              |
| `not_found`        | A valid response did not contain this hash                      |
| `breached`         | The hash was present, with `breach_count` occurrences           |
| `http_error`       | Have I Been Pwned returned an HTTP error                        |
| `network_error`    | The request did not complete                                    |
| `invalid_response` | A response arrived but was empty, truncated, or not well formed |

`not_found` means the password was absent from this dataset. It does not mean the password is safe or that it has never been compromised. A failed or malformed response leaves `breached` unset. It is never reported as `not_found`.

The request waits 10 seconds by default. Change that with `--timeout`.

## Reports

The command prints a card. In a terminal the frame is dim, the title is cyan and underlined, and each section title is bold cyan. Field labels such as Guesses are bold green.
The rating, the meter, and the score share one colour. A warning is yellow and a confirmed breach is red. `NO_COLOR` turns the colour off. `--json` prints one JSON document instead.

The card is 64 columns wide unless a warning or suggestion is longer. It then grows to fit that tip, and stops 10 columns short of the terminal. Anything longer wraps.

Lookalikes, Banned, and Policy appear on the card only when that part of the report applies. A password with no lookalikes, no banned list, and no policy omits those sections.

This card is illustrative. The breach count is not a live result.

```text
╭────────────────────────────────────────────────────────────────────────╮
│                           Password Strength                            │
│                                                                        │
│  Compromised                                                  0 / 100  │
│  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  │
│  zxcvbn:                                                        1 / 4  │
├───────────────────────────── Composition ──────────────────────────────┤
│  Length:                 12      Unique characters: 10                 │
│  Character classes:      4       Lowercase:        7                   │
│  Uppercase:              1       Digits:           3                   │
│  Symbols:                1       Spaces:           0                   │
│  Other Unicode:          0                                             │
├─────────────────────────────── Guessing ───────────────────────────────┤
│  Guesses:                1,200                                         │
│  Entropy:                10.23 bits                                    │
│                                                                        │
│  Online (Throttled):     12 hours                                      │
│  Online (Unthrottled):   2 minutes                                     │
│  Offline (Slow Hash):    less than a second                            │
│  Offline (Fast Hash):    less than a second                            │
├──────────────────────────────── Advice ────────────────────────────────┤
│  Warning:                This is similar to a commonly used password.  │
│  Suggestions:            • Add another word or two.                    │
│                          • Uncommon words are better.                  │
├──────────────────────────────── Breach ────────────────────────────────┤
│  Breached. 123,456 occurrences.                                        │
╰────────────────────────────────────────────────────────────────────────╯
```

> [!NOTE]
> The Python zxcvbn package uses older dictionaries and heuristics. Treat its score as an estimate, not a final security verdict.

<!-- -->

> [!NOTE]
> A confirmed breach or a banned-list hit forces the overall score to zero. If either check fails or the list cannot be read, the zxcvbn score is still reported and the status says why the result could not be trusted.

<a href="https://github.com/the-lupaxa-project">
  <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/components/footer-for-child-orgs.svg" alt="The Lupaxa Project Footer" width="100%" />
</a>

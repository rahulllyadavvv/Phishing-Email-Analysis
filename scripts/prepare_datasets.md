# Preparing a training CSV for the tone model

`scripts/train_tone_model.py` expects one CSV with two columns:

| column | meaning |
|---|---|
| `text` | the email text (subject + body; HTML is stripped by the script) |
| `label` | `1` = phishing, `0` = legitimate |

Keep real phishing mail out of the repository: build the CSV under `samples/` (gitignored) or
outside the project.

## Public sources

| Source | Label | Notes |
|---|---|---|
| **Nazario phishing corpus** (monkey.org/~jose/phishing) | 1 | mbox files by year; the classic phishing set |
| **SpamAssassin public corpus** (spamassassin.apache.org/old/publiccorpus) | `easy_ham`, `hard_ham` -> 0 | skip its `spam` folders (spam is not phishing) |
| **Enron email dataset** (CMU) | 0 | large amount of legitimate business mail |
| **CEAS 2008 / TREC 2007** | mixed | check each set's license and labels before use |
| **PhishTank / OpenPhish** | - | URL feeds, not email text; not usable here |

Read each corpus's license and terms before using it, and do not redistribute the data.

## Steps

1. **Extract** subject and body from each message (mbox / maildir). Python's `mailbox` and
   `email` modules are enough: take the `text/plain` part, or the `text/html` part when there is
   no plain part (the training script strips HTML). Put the subject first:
   `"<subject>\n\n<body>"`.
2. **Remove headers and signatures that give the label away**, such as corpus-specific footers,
   "[SPAM]" tags added by a filter, or anonymized addresses like `jose@monkey.org`. Otherwise the
   model learns the corpus instead of the phishing.
3. **De-duplicate.** Phishing corpora contain many near-identical copies. Drop exact duplicates
   after whitespace normalization (the script also drops exact duplicates), and consider
   near-duplicate removal (for example MinHash, or the same first 200 characters).
4. **Balance.** Legitimate mail usually outnumbers phishing by a lot. Down-sample the majority
   class to at most about 2-3x the minority class, or the model learns to say "legitimate".
   Keep a note of the original ratio for evaluation.
5. **Mix the time periods.** Take phishing from several years so the model does not just learn
   one campaign's wording.
6. **Write the CSV** with the `csv` module (it quotes newlines and commas correctly):

   ```python
   import csv
   with open("samples/tone.csv", "w", newline="", encoding="utf-8") as f:
       writer = csv.writer(f)
       writer.writerow(["text", "label"])
       writer.writerows(rows)  # (text, 0 or 1)
   ```

7. **Train:**

   ```bash
   pip install -e ".[ml]"
   python scripts/train_tone_model.py --csv samples/tone.csv --output models/tone --epochs 3
   ```

   Then set `TONE_MODEL_PATH=models/tone` in `.env`.

## Evaluating honestly

The script reports precision, recall, F1 and a confusion matrix on a held-out, stratified test
split. Public corpora are old and clean, so scores on them overstate real-world performance.
Before relying on the model, check it on a small set of your own recent, hand-labelled mail
(Phase 14).

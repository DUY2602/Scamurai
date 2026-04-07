import json

with open('Email/models/email_eval_report.json', encoding='utf-8') as f:
    r = json.load(f)

m = r['test_metrics']
print('=== TEST METRICS ===')
print(f'Samples : {m["total_samples"]:,} (ham={m["ham_samples"]:,}, spam={m["spam_samples"]:,})')
print(f'Accuracy: {m["accuracy"]:.4f}')
print(f'ROC-AUC : {m["roc_auc"]:.4f}')
print(f'MacroF1 : {m["macro_f1"]:.4f}')
print(f'Prec    : {m["precision_spam"]:.4f}')
print(f'Recall  : {m["recall_spam"]:.4f}')
print(f'F1-Spam : {m["f1_spam"]:.4f}')
print(f'FPR     : {m["false_positive_rate"]:.4f}')
print(f'FNR     : {m["false_negative_rate"]:.4f}')
print(f'TP={m["true_positives"]} TN={m["true_negatives"]} FP={m["false_positives"]} FN={m["false_negatives"]}')
print()
print('=== THRESHOLD SWEEP ===')
print(f'{"Thresh":>6}  {"Accuracy":>8}  {"Prec":>6}  {"Recall":>6}  {"F1":>6}  {"MacroF1":>7}  {"FPR":>6}  {"FNR":>6}')
for row in r['threshold_sweep']:
    mark = ' <-- selected' if abs(row['threshold'] - m['threshold']) < 0.001 else ''
    print(f'{row["threshold"]:>6.2f}  {row["accuracy"]:>8.4f}  {row["precision_spam"]:>6.4f}  {row["recall_spam"]:>6.4f}  {row["f1_spam"]:>6.4f}  {row["macro_f1"]:>7.4f}  {row["false_positive_rate"]:>6.4f}  {row["false_negative_rate"]:>6.4f}{mark}')

print()
print('=== SANITY CHECKS ===')
passed = 0
for s in r['sanity_checks']:
    ok = 'PASS' if s['correct'] else 'FAIL'
    if s['correct']:
        passed += 1
    print(f'  [{ok}] {s["subject"][:45]:<45} -> {s["predicted"].upper()} (prob={s["spam_probability"]:.4f})')
print(f'  Result: {passed}/{len(r["sanity_checks"])} passed')

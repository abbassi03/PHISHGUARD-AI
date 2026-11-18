# Experimental protocol

## Research questions

1. Which URL lexical and structural characteristics carry the strongest signal for distinguishing phishing from legitimate URLs?
2. Which classical model offers the best precision/recall/F1 trade-off for the phishing class?
3. How do results change when registered domains are isolated across train, validation and test?
4. Can model behaviour be explained with global feature importance and optional local SHAP values?

## Feature schema

The ordered features are defined in `phishguard.features.url_features.FEATURE_NAMES`. The extractor runs both during training and inference; the same function and feature order are used in both paths.

## Candidate models

- Logistic Regression (scaled numeric features; class-balanced baseline)
- Decision Tree (depth-limited, class-balanced)
- Random Forest (class-balanced ensemble)
- Extra Trees (class-balanced ensemble)

## Split strategy

`StratifiedGroupKFold` is applied with registered domain as the group. Approximately 20% is held out for test. The remaining rows are split again by group into validation and train, yielding approximately 60/20/20. Group intersections are checked and a run fails if domain leakage is detected or one of the splits loses a class.

## Threshold and model selection

For each candidate, the threshold maximizing phishing-class F1 is selected on validation probabilities only. The model is selected by validation F1. The held-out test partition is then evaluated for final reporting. Test metrics must not be used to tune model parameters or the threshold.

## Reported metrics

Accuracy, balanced accuracy, precision/recall/F1 for phishing, ROC-AUC, PR-AUC, false-positive rate, false-negative rate and confusion matrix.

## Interpretation warnings

- This protocol is not a temporal test and does not prove performance on future phishing campaigns.
- Domain isolation reduces, but does not eliminate, distribution and collection bias.
- Model importance is not causal evidence.
- The output score may be miscalibrated, especially under dataset shift.

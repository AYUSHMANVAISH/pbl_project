from rules import cicids_rule_detection

def final_decision(row, ml_prediction):

    rule_result = cicids_rule_detection(row)

    if rule_result != "Normal":
        return rule_result
    elif ml_prediction == -1:
        return "Unknown Anomalous Traffic"
    else:
        return "Normal Traffic"

def final_decision_rf(row, rf_prediction, rf_probability):
    rule_result = cicids_rule_detection(row)

    if rule_result != "Normal":
        return rule_result
    elif rf_prediction == 1:
        if rf_probability > 0.8:
            return "High Confidence Attack"
        elif rf_probability > 0.5:
            return "Medium Confidence Attack"
        elif rf_probability > 0.3:
            return "Low Confidence Attack"
        else:
            return "Suspected Anomalous Traffic"
    elif rf_probability > 0.3:
        return "Suspected Anomalous Traffic"
    else:
        return "Normal Traffic"

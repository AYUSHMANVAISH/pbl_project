import pytest
import pandas as pd
import numpy as np

class TestRules:

    def test_detect_ddos_high_request_rate(self):
        from rules import detect_ddos
        row = {'request_rate': 1500, 'request_count': 100}
        assert detect_ddos(row) == True

    def test_detect_ddos_high_request_count(self):
        from rules import detect_ddos
        row = {'request_rate': 100, 'request_count': 6000}
        assert detect_ddos(row) == True

    def test_detect_ddos_normal_traffic(self):
        from rules import detect_ddos
        row = {'request_rate': 50, 'request_count': 100}
        assert detect_ddos(row) == False

    def test_cicids_rule_detection_ddos(self):
        from rules import cicids_rule_detection
        row = {'request_rate': 2000, 'request_count': 100, 'avg_duration': 500}
        assert cicids_rule_detection(row) == "DDoS Attack"

    def test_cicids_rule_detection_normal(self):
        from rules import cicids_rule_detection
        row = {'request_rate': 50, 'request_count': 100, 'avg_duration': 500}
        assert cicids_rule_detection(row) == "Normal"

class TestModel:

    def test_train_isolation_forest(self):
        from model import train_isolation_forest

        features = pd.DataFrame({
            'request_count': [100, 200, 150, 500, 120] * 20,
            'request_rate': [50, 100, 75, 200, 60] * 20,
            'avg_duration': [1000, 2000, 1500, 500, 800] * 20
        })

        model = train_isolation_forest(features, contamination=0.1)
        assert model is not None
        assert hasattr(model, 'predict')

    def test_get_anomaly_scores(self):
        from model import train_isolation_forest, get_anomaly_scores

        features = pd.DataFrame({
            'request_count': [100, 200, 150, 5000, 120] * 20,
            'request_rate': [50, 100, 75, 2000, 60] * 20,
            'avg_duration': [1000, 2000, 1500, 500, 800] * 20
        })

        model = train_isolation_forest(features, contamination=0.1)
        scores, predictions = get_anomaly_scores(model, features)

        assert len(scores) == len(features)
        assert len(predictions) == len(features)
        assert set(predictions.unique()).issubset({-1, 1})

class TestEvaluation:

    def test_calculate_metrics(self):
        from evaluation import calculate_metrics

        y_true = {1, 2, 3, 4, 5}
        y_pred = {1, 2, 3, 6, 7}

        metrics = calculate_metrics(y_true, y_pred)

        assert metrics['true_positives'] == 3
        assert metrics['false_positives'] == 2
        assert metrics['false_negatives'] == 2
        assert 0 <= metrics['precision'] <= 1
        assert 0 <= metrics['recall'] <= 1
        assert 0 <= metrics['f1'] <= 1

    def test_calculate_metrics_perfect(self):
        from evaluation import calculate_metrics

        y_true = {1, 2, 3}
        y_pred = {1, 2, 3}

        metrics = calculate_metrics(y_true, y_pred)

        assert metrics['precision'] == 1.0
        assert metrics['recall'] == 1.0
        assert metrics['f1'] == 1.0

class TestDetector:

    def test_final_decision_rule_based(self):
        from detector import final_decision

        row = {'request_rate': 2000, 'request_count': 100, 'avg_duration': 500}
        decision = final_decision(row, ml_prediction=1)
        assert decision == "DDoS Attack"

    def test_final_decision_ml_based(self):
        from detector import final_decision

        row = {'request_rate': 50, 'request_count': 100, 'avg_duration': 500}
        decision = final_decision(row, ml_prediction=-1)
        assert decision == "Unknown Anomalous Traffic"

    def test_final_decision_normal(self):
        from detector import final_decision

        row = {'request_rate': 50, 'request_count': 100, 'avg_duration': 500}
        decision = final_decision(row, ml_prediction=1)
        assert decision == "Normal Traffic"

if __name__ == '__main__':
    pytest.main([__file__, '-v'])

import pytest
import pandas as pd
import numpy as np
from detector import final_decision, final_decision_rf
from rules import cicids_rule_detection, detect_ddos

class TestMixedTrafficScenarios:

    def test_high_attack_ratio_port(self):
        row = {
            'request_rate': 800,
            'request_count': 4000,
            'avg_duration': 100
        }
        result = cicids_rule_detection(row)
        assert result in ["Normal", "DDoS Attack", "High Volume Traffic", "PortScan Attack"]

    def test_low_attack_ratio_port(self):
        row = {
            'request_rate': 200,
            'request_count': 1000,
            'avg_duration': 500
        }
        result = cicids_rule_detection(row)
        assert result == "Normal"

    def test_pure_attack_port(self):
        row = {
            'request_rate': 2000,
            'request_count': 6000,
            'avg_duration': 50
        }
        result = cicids_rule_detection(row)
        assert result == "DDoS Attack"

class TestDetectionThresholds:

    def test_ddos_threshold_boundary(self):
        row_below = {'request_rate': 499, 'request_count': 100}
        assert detect_ddos(row_below) == False

        row_at = {'request_rate': 500, 'request_count': 100}
        assert detect_ddos(row_at) == False

        row_above = {'request_rate': 501, 'request_count': 100}
        assert detect_ddos(row_above) == True

    def test_rf_probability_thresholds(self):
        row = {'request_rate': 50, 'request_count': 100, 'avg_duration': 500}

        decision_high = final_decision_rf(row, rf_prediction=1, rf_probability=0.85)
        assert decision_high == "High Confidence Attack"

        decision_med = final_decision_rf(row, rf_prediction=1, rf_probability=0.65)
        assert decision_med == "Medium Confidence Attack"

        decision_low = final_decision_rf(row, rf_prediction=1, rf_probability=0.4)
        assert decision_low == "Low Confidence Attack"

        decision_vlow = final_decision_rf(row, rf_prediction=0, rf_probability=0.2)
        assert decision_vlow == "Normal Traffic"

class TestPortLevelAggregation:

    def test_averaging_dilutes_signal(self):
        attack_flows = pd.DataFrame({
            'packets_per_sec': [5000, 4800, 5200],
            'request_rate': [2000, 1900, 2100]
        })
        benign_flows = pd.DataFrame({
            'packets_per_sec': [100, 120, 90],
            'request_rate': [50, 60, 45]
        })

        all_flows = pd.concat([attack_flows, benign_flows])
        avg_packets = all_flows['packets_per_sec'].mean()
        avg_rate = all_flows['request_rate'].mean()

        assert avg_packets < 3000
        assert avg_rate < 1100

        assert avg_packets > benign_flows['packets_per_sec'].mean()

    def test_max_preserves_signal(self):
        attack_flows = pd.DataFrame({
            'packets_per_sec': [5000, 4800, 5200],
        })
        benign_flows = pd.DataFrame({
            'packets_per_sec': [100, 120, 90],
        })

        all_flows = pd.concat([attack_flows, benign_flows])

        max_packets = all_flows['packets_per_sec'].max()
        assert max_packets == 5200

        mean_packets = all_flows['packets_per_sec'].mean()
        assert mean_packets < 3000

class TestDetectionCoverage:

    def test_zero_traffic(self):
        row = {
            'request_rate': 0,
            'request_count': 0,
            'avg_duration': 0
        }
        result = cicids_rule_detection(row)
        assert result == "Normal"

    def test_missing_features(self):
        row = {
            'request_rate': 0,
            'request_count': 100,
            'avg_duration': 500
        }
        result = cicids_rule_detection(row)
        assert result == "Normal"

    def test_extreme_values(self):
        row = {
            'request_rate': 999999,
            'request_count': 999999,
            'avg_duration': 1
        }
        result = cicids_rule_detection(row)
        assert result in ["DDoS Attack", "High Volume Traffic"]

class TestModelConsistency:

    def test_rule_vs_ml_agreement(self):
        row = {
            'request_rate': 3000,
            'request_count': 8000,
            'avg_duration': 100
        }

        rule_result = cicids_rule_detection(row)
        assert rule_result == "DDoS Attack"

        ml_result = final_decision(row, ml_prediction=-1)
        assert ml_result == "DDoS Attack"

    def test_ml_only_detection(self):
        row = {
            'request_rate': 500,
            'request_count': 1000,
            'avg_duration': 600
        }

        rule_result = cicids_rule_detection(row)
        assert rule_result == "PortScan Attack"

        row2 = {
            'request_rate': 299,
            'request_count': 999,
            'avg_duration': 600
        }
        rule_result2 = cicids_rule_detection(row2)
        assert rule_result2 == "Normal"

        ml_result = final_decision(row2, ml_prediction=-1)
        assert ml_result == "Unknown Anomalous Traffic"

if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])

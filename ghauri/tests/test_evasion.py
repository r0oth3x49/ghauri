#!/usr/bin/python3
# -*- coding: utf-8 -*-
# pylint: disable=R,W,E,C

import unittest
from unittest.mock import patch, MagicMock

# Assuming ghauri is in PYTHONPATH or installed
from ghauri.evasion.quantum_waf_evasion import QuantumWAFEvasion, apply_quantum_evasion, learn_from_response
from ghauri.common.config import conf # Global conf object
from ghauri.common.lib import DBMS_DICT # For DBMS names

class TestQuantumWAFEvasion(unittest.TestCase):
    def setUp(self):
        """Set up for test methods."""
        # We can instantiate a new engine for each test or for the whole class
        # Forcing epsilon to 0 for predictable exploitation in some tests, 1 for exploration
        self.engine_exploit = QuantumWAFEvasion(epsilon=0.0, mutation_rate=0.1, learning_rate=0.1)
        self.engine_explore = QuantumWAFEvasion(epsilon=1.0, mutation_rate=0.1, learning_rate=0.1)
        
        self.generic_context = {"dbms": "generic", "type": "sql"}
        self.mysql_context = {"dbms": DBMS_DICT.get("mysql"), "type": "sql"} # Use actual name from DBMS_DICT
        self.mssql_context = {"dbms": DBMS_DICT.get("mssql"), "type": "sql"}
        self.psql_context = {"dbms": DBMS_DICT.get("postgresql"), "type": "sql"}
        self.oracle_context = {"dbms": DBMS_DICT.get("oracle"), "type": "sql"}

        # Store original conf values to restore in tearDown
        self.original_conf_backend = conf.backend
        self.original_conf_quantum_level = conf.quantum_evasion_level
        self.original_conf_quantum_morphological = conf.quantum_morphological
        self.original_conf_quantum_semantic = conf.quantum_semantic
        self.original_conf_quantum_syntactic = conf.quantum_syntactic
        self.original_conf_quantum_superposition = conf.quantum_superposition

        # Set default conf for tests - methods in QuantumWAFEvasion read from global conf
        conf.backend = "generic"
        conf.quantum_evasion_level = 1
        conf.quantum_morphological = True
        conf.quantum_semantic = True
        conf.quantum_syntactic = True
        conf.quantum_superposition = False # Usually for optimized payload

    def tearDown(self):
        """Clean up after test methods."""
        conf.backend = self.original_conf_backend
        conf.quantum_evasion_level = self.original_conf_quantum_level
        conf.quantum_morphological = self.original_conf_quantum_morphological
        conf.quantum_semantic = self.original_conf_quantum_semantic
        conf.quantum_syntactic = self.original_conf_quantum_syntactic
        conf.quantum_superposition = self.original_conf_quantum_superposition
        # Reset Q-table for engines if necessary, or re-instantiate them in setUp

    def test_initialization(self):
        """Test engine initialization and default epsilon usage from conf."""
        original_epsilon = conf.quantum_epsilon
        conf.quantum_epsilon = 0.25
        engine = QuantumWAFEvasion() # Should pick up from conf
        self.assertEqual(engine.epsilon, 0.25)
        conf.quantum_epsilon = original_epsilon # Reset

        engine_custom = QuantumWAFEvasion(epsilon=0.5)
        self.assertEqual(engine_custom.epsilon, 0.5)

    def test_morphological_transformation_basic(self):
        """Test basic morphological transformations (case, comments)."""
        conf.quantum_morphological = True
        payload = "SELECT FROM users WHERE id=1"
        # Test with generic context, as specific comment logic is complex for unit testing randomness
        transformed = self.engine_exploit._morphological_transformation(payload, self.generic_context)
        self.assertNotEqual(payload, transformed, "Payload should be morphed.")
        # Check for common characteristics - this is tricky due to randomness
        # For a more deterministic test, one might need to mock random.random or random.choice
        # or test sub-components of morphological_transformation if they were refactored.
        self.assertTrue(any(c in transformed for c in "/**/")) # Check if comments were added (if space replacement happened)
        
        # Test keyword case manipulation (hard to test exact output due to randomness)
        # We can check if it's different or if specific patterns emerge if we fix random seed.
        # For now, just ensure it runs and produces a different output.
        keyword = "SELECT"
        morphed_keyword = self.engine_exploit._morphological_transformation(keyword, self.generic_context)
        self.assertNotEqual(keyword, morphed_keyword, "Keyword should have case morphed or comments added.")

    def test_syntactic_obfuscation_comments_mysql(self):
        """Test MySQL comment injection (conceptual, as current method is broad)."""
        conf.quantum_syntactic = True # Assuming comments are part of syntactic or morphological
        conf.quantum_morphological = True 
        payload = "SELECT 1"
        # The _morphological_transformation handles comments based on context
        transformed = self.engine_exploit._morphological_transformation(" ", self.mysql_context) # Test space replacement
        self.assertTrue(any(c in transformed for c in self.engine_exploit.dbms_specific_comments["mysql"]))

    def test_syntactic_obfuscation_char_encoding_mysql(self):
        """Test CHAR() encoding for MySQL within syntactic obfuscation."""
        conf.quantum_syntactic = True
        # Mock random.random() to force specific path if needed, or check for pattern
        # Current _syntactic_obfuscation has random parts for char encoding.
        # This test will be more of a "does it run and produce something plausible"
        segment = "A"
        with patch.object(random, 'random', side_effect=[0.4, 0.4]): # Force path to char encoding, then MySQL path
             transformed = self.engine_exploit._syntactic_obfuscation(segment, self.mysql_context)
        self.assertIn("CHAR(65)", transformed.upper(), "Should use CHAR() for MySQL for 'A'")

    def test_semantic_preservation_concat_dbms(self):
        """Test DBMS-aware concatenation (conceptual)."""
        # This tests the self.dbms_specific_concat dictionary via a hypothetical path
        conf.quantum_semantic = True
        # Example: 'A' 'B' -> CONCAT('A','B') for MySQL
        # The current _semantic_preservation doesn't directly expose this.
        # We are testing the stored lambda functions.
        self.assertEqual(self.engine_exploit.dbms_specific_concat["mysql"]("'A'", "'B'"), "CONCAT('A','B')")
        self.assertEqual(self.engine_exploit.dbms_specific_concat["postgresql"]("'A'", "'B'"), "'A'||'B'")
        self.assertEqual(self.engine_exploit.dbms_specific_concat["mssql"]("'A'", "'B'"), "'A'+'B'")


    def test_metamorphic_encoding_hex_mysql(self):
        """Test hex encoding part of metamorphic for MySQL."""
        conf.quantum_metamorphic = True
        conf.quantum_evasion_level = 1 # For predictable layers
        segment_to_encode = "test"
        # Mock random.random() to force the hex encoding path in _metamorphic_encoding
        with patch.object(random, 'random', return_value=0.5): # To trigger hex encoding path
            with patch.object(random, 'sample', return_value=[0,len(segment_to_encode)]): # To hex encode whole segment
                 transformed = self.engine_exploit._metamorphic_encoding(segment_to_encode, self.mysql_context)
        self.assertIn(f"0x{segment_to_encode.encode().hex()}", transformed, "Should contain MySQL style 0x hex encoding.")

    def test_apply_transformations_with_dbms_context(self):
        """Test that apply_transformations uses context and produces different results."""
        conf.quantum_morphological = True
        conf.quantum_syntactic = True
        payload = "SELECT id FROM users"
        
        # MySQL - might add # or /**/
        transformed_mysql = self.engine_exploit.apply_transformations(payload, self.mysql_context)
        # SQL Server - might add -- or /**/
        transformed_mssql = self.engine_exploit.apply_transformations(payload, self.mssql_context)
        
        self.assertNotEqual(payload, transformed_mysql)
        self.assertNotEqual(payload, transformed_mssql)
        # It's hard to guarantee mysql vs mssql will be different due to shared comment types (/**/)
        # and randomness, but they should at least be transformed.
        self._log(f"MySQL Transformed: {transformed_mysql}")
        self._log(f"MSSQL Transformed: {transformed_mssql}")


    def test_superposition_payload_generation(self):
        """Test _superposition_payload_generation returns multiple variants."""
        conf.quantum_superposition = True # Enable superposition
        payload = "SELECT * FROM test"
        variants = self.engine_exploit._superposition_payload_generation(payload, num_variants=3, context_vector=self.generic_context)
        self.assertIsInstance(variants, list)
        self.assertTrue(len(variants) >= 1) # Should be 3 unless level is low and forces less.
        if variants:
            self.assertNotEqual(payload, variants[0], "Generated variant should differ from original.")
        conf.quantum_superposition = False # Reset

    @patch.object(QuantumWAFEvasion, '_calculate_evasion_score')
    def test_generate_optimized_payload_exploitation(self, mock_calc_score):
        """Test generate_optimized_payload in exploitation mode (epsilon=0)."""
        self.engine_exploit.epsilon = 0.0 # Force exploitation
        payload = "SELECT id FROM data"
        
        # Setup variants and their mocked scores
        variant1 = "SELECT/**/id/**/FROM/**/data"
        variant2 = "sElEcT Id fRoM DaTa"
        # Mock _superposition_payload_generation to return predictable variants
        self.engine_exploit._superposition_payload_generation = MagicMock(return_value=[variant1, variant2])

        # Mock scores: variant2 is better
        def score_side_effect(p_variant, context):
            if p_variant == variant1: return 0.5
            if p_variant == variant2: return 0.8
            return 0.0
        mock_calc_score.side_effect = score_side_effect
        
        optimized = self.engine_exploit.generate_optimized_payload(payload, self.generic_context)
        self.assertEqual(optimized, variant2)

    def test_generate_optimized_payload_exploration(self):
        """Test generate_optimized_payload in exploration mode (epsilon=1)."""
        self.engine_explore.epsilon = 1.0 # Force exploration
        payload = "SELECT id FROM data"
        
        variant1 = "SELECT/**/id/**/FROM/**/data"
        variant2 = "sElEcT Id fRoM DaTa"
        variants = [variant1, variant2]
        self.engine_explore._superposition_payload_generation = MagicMock(return_value=variants)
        
        optimized = self.engine_explore.generate_optimized_payload(payload, self.generic_context)
        self.assertIn(optimized, variants)

    def test_adaptive_learning_updates_q_table(self):
        """Test basic Q-table update via adaptive_learning."""
        payload = "TEST PAYLOAD"
        context = self.generic_context
        state_key = self.engine_exploit._get_state_representation(payload, context)

        self.assertNotIn(state_key, self.engine_exploit.q_table)
        
        # Simulate a successful payload
        feedback_data = [(payload, 200, context, True)]
        self.engine_exploit.adaptive_learning(feedback_data)
        
        self.assertIn(state_key, self.engine_exploit.q_table)
        self.assertTrue(self.engine_exploit.q_table[state_key]["last_success"])
        self.assertEqual(self.engine_exploit.q_table[state_key]["attempts"], 1)
        self.assertGreater(self.engine_exploit.q_table[state_key]["overall_score"], 0)

        # Simulate a failed payload
        original_score = self.engine_exploit.q_table[state_key]["overall_score"]
        feedback_data_fail = [(payload, 403, context, False)]
        self.engine_exploit.adaptive_learning(feedback_data_fail)
        
        self.assertFalse(self.engine_exploit.q_table[state_key]["last_success"])
        self.assertEqual(self.engine_exploit.q_table[state_key]["attempts"], 2)
        self.assertLess(self.engine_exploit.q_table[state_key]["overall_score"], original_score)

    def test_apply_quantum_evasion_helper(self):
        """Test the apply_quantum_evasion helper function."""
        payload = "SELECT 1"
        # Check it calls the engine's method
        with patch.object(self.engine_exploit, 'generate_optimized_payload', return_value="mocked_payload") as mock_gen:
            conf.quantum_superposition = True # Enable superposition path
            result = apply_quantum_evasion(payload, self.generic_context, self.engine_exploit)
            mock_gen.assert_called_once_with(payload, self.generic_context)
            self.assertEqual(result, "mocked_payload")
        
        with patch.object(self.engine_exploit, 'apply_transformations', return_value="mocked_transformed") as mock_transform:
            conf.quantum_superposition = False # Disable superposition path
            result = apply_quantum_evasion(payload, self.generic_context, self.engine_exploit)
            mock_transform.assert_called_once_with(payload, self.generic_context)
            self.assertEqual(result, "mocked_transformed")

    def test_learn_from_response_helper(self):
        """Test the learn_from_response helper function."""
        with patch.object(self.engine_exploit, 'adaptive_learning') as mock_learn:
            learn_from_response("payload", 200, self.generic_context, True, self.engine_exploit)
            mock_learn.assert_called_once()
            # Check if payload_history was updated
            self.assertTrue(any(item[0] == "payload" for item in self.engine_exploit.payload_history))


if __name__ == '__main__':
    unittest.main()

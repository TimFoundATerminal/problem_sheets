import unittest
from spn_components import SBOX, SubstitutionLayer, PermutationLayer, format_state

class TestSBOX(unittest.TestCase):
    def test_default_sbox_initialization(self):
        """Test initialization with default S-box"""
        sbox = SBOX()
        self.assertEqual(sbox.bits, 4)
        self.assertEqual(sbox.size, 16)
        self.assertEqual(len(sbox.table), 16)
        
        # Check default table values
        expected_table = [
            0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
            0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2
        ]
        self.assertEqual(sbox.table, expected_table)
        
    def test_custom_sbox_initialization(self):
        """Test initialization with custom S-box"""
        custom_table = [3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12]
        sbox = SBOX(table=custom_table)
        self.assertEqual(sbox.table, custom_table)
        
    def test_invalid_sbox_size(self):
        """Test initialization with invalid S-box size"""
        invalid_table = [0, 1, 2, 3, 4, 5]  # Too short
        with self.assertRaises(ValueError):
            SBOX(table=invalid_table)
            
    def test_non_bijective_sbox(self):
        """Test initialization with non-bijective S-box"""
        non_bijective = [0, 1, 2, 3, 4, 5, 6, 7, 0, 9, 10, 11, 12, 13, 14, 15]  # 0 appears twice
        with self.assertRaises(ValueError):
            SBOX(table=non_bijective)
            
    def test_inverse_computation(self):
        """Test inverse S-box computation"""
        sbox = SBOX()
        # For each value in the table, the inverse should map back
        for i in range(sbox.size):
            self.assertEqual(i, sbox.inverse[sbox.table[i]])
            
    def test_binary_conversion(self):
        """Test binary conversion methods"""
        sbox = SBOX()
        
        # Integer to binary
        self.assertEqual(sbox._convert_to_binary(5), [1, 0, 1, 0])  # 5 = 0101 in binary
        self.assertEqual(sbox._convert_to_binary(10), [0, 1, 0, 1])  # 10 = 1010 in binary
        
        # Binary to integer
        self.assertEqual(sbox._convert_to_int([1, 0, 1, 0]), 5)
        self.assertEqual(sbox._convert_to_int([0, 1, 0, 1]), 10)
        
    def test_encrypt_decrypt(self):
        """Test encryption and decryption"""
        sbox = SBOX()
        
        # Test a few input values
        test_values = [
            [0, 0, 0, 0],  # 0
            [1, 0, 0, 0],  # 1
            [0, 1, 0, 0],  # 2
            [1, 0, 1, 0],  # 5
            [1, 1, 1, 1]   # 15
        ]
        
        for value in test_values:
            # Encrypt and then decrypt should return the original value
            encrypted = sbox.encrypt(value)
            decrypted = sbox.decrypt(encrypted)
            self.assertEqual(decrypted, value, f"Failed for value {value}")

class TestSubstitutionLayer(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures"""
        # Create 4 different SBOXes for testing
        self.sbox1 = SBOX()  # Default SBOX
        
        # Custom SBOXes
        self.sbox2 = SBOX(table=[
            0x3, 0x8, 0xF, 0x1, 0xA, 0x6, 0x5, 0xB,
            0xE, 0xD, 0x4, 0x2, 0x7, 0x0, 0x9, 0xC
        ])
        self.sbox3 = SBOX(table=[
            0x7, 0xD, 0xE, 0x3, 0x0, 0x6, 0x9, 0xA,
            0x1, 0x2, 0x8, 0x5, 0xB, 0xC, 0x4, 0xF
        ])
        self.sbox4 = SBOX(table=[
            0x2, 0xC, 0x4, 0x1, 0x7, 0xA, 0xB, 0x6,
            0x8, 0x5, 0x3, 0xF, 0xD, 0x0, 0xE, 0x9
        ])
        
    def test_substitution_layer_initialization(self):
        """Test initialization of substitution layer"""
        sboxes = [self.sbox1, self.sbox2, self.sbox3, self.sbox4]
        sub_layer = SubstitutionLayer(sboxes, 16)  # 4 SBOXes * 4 bits each = 16 bits
        
        self.assertEqual(sub_layer.length, 16)
        self.assertEqual(sub_layer.bits, 4)
        self.assertEqual(len(sub_layer.sboxes), 4)
        
    def test_invalid_substitution_layer(self):
        """Test initialization with invalid parameters"""
        sboxes = [self.sbox1, self.sbox2, self.sbox3]  # Only 3 SBOXes
        
        # 3 SBOXes * 4 bits each = 12 bits, but we specify 16
        with self.assertRaises(ValueError):
            SubstitutionLayer(sboxes, 16)
            
    def test_substitution_layer_encrypt_decrypt(self):
        """Test encryption and decryption with substitution layer"""
        sboxes = [self.sbox1, self.sbox2, self.sbox3, self.sbox4]
        sub_layer = SubstitutionLayer(sboxes, 16)
        
        # Create a 16-bit test state
        state = [0, 0, 0, 1,  # First 4 bits = 1
                 0, 1, 0, 0,  # Next 4 bits = 4
                 1, 0, 0, 0,  # Next 4 bits = 8
                 1, 1, 1, 1]  # Last 4 bits = 15
        
        # Encrypt and decrypt
        encrypted = sub_layer.encrypt(state)
        decrypted = sub_layer.decrypt(encrypted)
        
        # After encryption and decryption, we should get back the original state
        self.assertEqual(decrypted, state)

class TestPermutationLayer(unittest.TestCase):
    def test_permutation_layer_initialization(self):
        """Test initialization of permutation layer"""
        # Create a simple 8-bit permutation that swaps bit positions
        perm_map = {
            0: 4, 
            1: 5, 
            2: 6, 
            3: 7, 
            4: 0, 
            5: 1, 
            6: 2, 
            7: 3
        }
        perm_layer = PermutationLayer(perm_map)
        
        self.assertEqual(perm_layer.length, 8)
        self.assertEqual(perm_layer.permutation, perm_map)
        
    def test_invalid_permutation_map(self):
        """Test initialization with invalid permutation map"""
        # Map with out-of-range values
        invalid_map = {0: 10, 1: 1, 2: 2, 3: 3}
        with self.assertRaises(ValueError):
            PermutationLayer(invalid_map)
            
        # Map with duplicate positions
        invalid_map = {0: 1, 1: 1, 2: 2, 3: 3}
        with self.assertRaises(ValueError):
            PermutationLayer(invalid_map)
            
    def test_permutation_encrypt_decrypt(self):
        """Test encryption and decryption with permutation layer"""
        # Create a permutation that rotates bits by 2 positions
        perm_map = {
            0: 2, 
            1: 3, 
            2: 4, 
            3: 5, 
            4: 6, 
            5: 7, 
            6: 0, 
            7: 1
        }
        perm_layer = PermutationLayer(perm_map)
        
        # Test state
        state = [1, 0, 1, 0, 1, 1, 0, 0]
        
        # Encrypt
        encrypted = perm_layer.encrypt(state)
        
        # Expected result after rotating by 2
        expected = [0, 0, 1, 0, 1, 0, 1, 1]
        self.assertEqual(encrypted, expected)
        
        # Decrypt
        decrypted = perm_layer.decrypt(encrypted)
        
        # Should get back the original state
        self.assertEqual(decrypted, state)
        
    def test_complex_permutation(self):
        """Test a more complex bit permutation"""
        # Bit shuffling permutation
        perm_map = {0: 7, 1: 3, 2: 5, 3: 1, 4: 6, 5: 2, 6: 4, 7: 0}
        perm_layer = PermutationLayer(perm_map)
        
        state = [1, 1, 1, 0, 0, 1, 0, 1]
        encrypted = perm_layer.encrypt(state)
        
        # Expected result after permutation
        expected = [1, 0, 1, 1, 0, 1, 0, 1]
        self.assertEqual(encrypted, expected)
        
        # Test round-trip
        decrypted = perm_layer.decrypt(encrypted)
        self.assertEqual(decrypted, state)

if __name__ == '__main__':
    unittest.main()
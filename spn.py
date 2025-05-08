from spn_components import SBOX, SubstitutionLayer, PermutationLayer, format_state, key_whitening, Layer
from random import shuffle

def generate_round_key(master_key, round_num, key_size=16):
    """Generate a round key for an SPN cipher using the formula 4r-3."""
    # Calculate the starting bit position using the formula 4r-3 (1-based index)
    start_pos = (4 * round_num) - 4
    end_pos = start_pos + key_size
    # Extract the key bits from the master key
    return master_key[start_pos:end_pos]


class SPN:
    def __init__(self, length: int=16):
        """SPN cipher with SBOXes, permutation, and key"""
        self.layers = []
        self.length = length
        self.num_rounds = 0
        self.key_round_function = None
        
    def add_layer(self, layer):
        """Add a layer to the SPN"""
        # Check if the layer is valid
        if not isinstance(layer, (SubstitutionLayer, PermutationLayer)):
            raise ValueError("Invalid layer type")
        # check the layer length
        if layer.length != self.length:
            raise ValueError("Invalid layer length")
        self.layers.append(layer)

    def add_key_whitening_layer(self):
        """Add key whitening layer to the SPN"""
        self.num_rounds += 1
        self.layers.append(key_whitening)

    def add_key_round_function(self, func: callable):
        """Add a custom round function to the SPN"""
        self.key_round_function = func

    def build_standard_spn(self, sbox: SBOX, permutation: dict, key_schedule: callable, num_rounds: int=4):
        """Build a standard SPN with SBOX and permutation layers"""
        sub_layer = SubstitutionLayer([sbox] * (self.length // sbox.bits), length=self.length)
        perm_layer = PermutationLayer(permutation)
        self.key_round_function = key_schedule
        
        for _ in range(num_rounds-1):
            self.add_key_whitening_layer()
            self.add_layer(sub_layer)
            self.add_layer(perm_layer)
        
        self.add_key_whitening_layer()
        self.add_layer(sub_layer)
        self.add_key_whitening_layer()
    
    def _check_master_key(self, master_key: list) -> None:
        """Check if the master key is valid"""
        if len(master_key) < self.length:
            raise ValueError("Invalid master key length")

    def encrypt(self, state: list, master_key: list) -> list:
        """Encrypt the state using the SPN cipher"""
        self._check_master_key(master_key)

        round_num = 1
        # Apply the SPN layers
        for layer in self.layers:
            if isinstance(layer, SubstitutionLayer):
                # Run state through the SBOX in reverse order
                state = layer.encrypt(state)
            elif isinstance(layer, PermutationLayer):
                # Run state through the permutation layer
                state = layer.encrypt(state)
            else: # Assume it's a key whitening function
                round_key = self.key_round_function(master_key, round_num) # Generate round key
                state = key_whitening(state, round_key) # Apply key whitening with round key
                round_num += 1

        return state
    
    # TODO: Figure out how you can alter the encryption method in order to perform decryption
    def decrypt_(self, state: list, master_key: list) -> list:
        """Decrypt the state using the SPN cipher by inverting SBOX and running through forward layers"""
        self._check_master_key(master_key)

        round_num = self.num_rounds
        for layer in self.layers:
            if isinstance(layer, SubstitutionLayer):
                # Run state through the SBOX in reverse order
                state = layer.decrypt(state)
            elif isinstance(layer, PermutationLayer):
                # Run state through the permutation layer
                state = layer.decrypt(state)
            else:
                round_key = self.key_round_function(master_key, round_num)
                state = key_whitening(state, round_key)
                round_num -= 1

        return state
    
    # def decrypt(self, state: list, master_key: list) -> list:
    #     """Decrypt the state using the SPN cipher by running the layers in reverse order"""
    #     self._check_master_key(master_key)

    #     round_num = self.num_rounds
    #     # Apply the SPN layers in reverse order
    #     for layer in reversed(self.layers):
    #         if isinstance(layer, Layer):
    #             # Run state through the layer
    #             state = layer.decrypt(state)
    #         else:
    #             round_key = self.key_round_function(master_key, round_num)
    #             state = key_whitening(state, round_key)
    #             round_num -= 1

    #     return state


def test_round_key_generation():
    # Test round key generation with 32-bit master key and 16-bit round keys
    master_key = [0,1,1,0, 1,0,1,0, 1,1,0,0, 0,1,0,1, 1,0,0,1, 0,1,1,0, 1,0,1,0, 1,1,0,0]
    round_key = generate_round_key(master_key, 1, key_size=16)
    print(round_key)
    assert(round_key == [0,1,1,0, 1,0,1,0, 1,1,0,0, 0,1,0,1])
    round_key = generate_round_key(master_key, 5, key_size=16)
    assert(round_key == [1,0,0,1, 0,1,1,0, 1,0,1,0, 1,1,0,0])


def create_spn() -> SPN:
    """Return a standard SPN with SBOX and permutation layers"""
    # Create an SPN with 16-bit state size
    spn: SPN = SPN(length=16)
    # Define the round key generation function
    spn.add_key_round_function(generate_round_key)
    
    # Create an SBOX with 4-bit input size
    sbox = SBOX(bits=4) # Uses the default SBOX table

    sub_layer: SubstitutionLayer = SubstitutionLayer([sbox, sbox, sbox, sbox], length=16)

    target = list(range(16))
    shuffle(target)
    perm_map = dict(zip(list(range(16)), target))
    perm_layer: PermutationLayer = PermutationLayer(perm_map)
    
    # Add the various layers to the SPN
    spn.add_key_whitening_layer()

    spn.add_layer(sub_layer)
    spn.add_layer(perm_layer)
    spn.add_key_whitening_layer()

    spn.add_layer(sub_layer)
    spn.add_layer(perm_layer)
    spn.add_key_whitening_layer()

    spn.add_layer(sub_layer)
    spn.add_layer(perm_layer)
    spn.add_key_whitening_layer()

    spn.add_layer(sub_layer)
    spn.add_key_whitening_layer()

    return spn


def test_spn():
    # Test SPN encryption and decryption
    spn = create_spn()

    print(spn.layers)
    
    # Test encryption and decryption
    plaintext = [1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0]
    master_key = [0,1,1,0, 1,0,1,0, 1,1,0,0, 0,1,0,1, 1,0,0,1, 0,1,1,0, 1,0,1,0, 1,1,0,0]
    encrypted = spn.encrypt(plaintext, master_key)
    decrypted = spn.decrypt_(encrypted, master_key)
    
    print(format_state(plaintext))
    print(format_state(encrypted))
    print(format_state(decrypted))
    
    assert(decrypted == plaintext)

if __name__ == "__main__":
    test_spn()
    print("All tests passed!")
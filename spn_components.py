def format_state(state: list, group_size=4) -> str:
    """Display the state in a readable format"""
    binary_string = ''.join(str(bit) for bit in state)
    # Add spaces every group_size characters
    chunks = [binary_string[i:i+group_size] for i in range(0, len(binary_string), group_size)]
    return ' '.join(chunks)


class Layer:
    """Base class for SPN layers"""
    def __init__(self, length: int):
        self.length = length

    def encrypt(self, state: list) -> list:
        """Encrypt the state"""
        raise NotImplementedError

    def decrypt(self, state: list) -> list:
        """Decrypt the state"""
        raise NotImplementedError


class SBOX:
    """SBOX class for SPN cipher"""
    def __init__(self, table: list=None, bits=4):
        self.bits = bits
        self.size = 2**bits

        if table is None:
            table = [
                0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
                0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2
            ]

        self._validate_table(table)
        self._compute_inverse()

    def _validate_table(self, table):
        """Check if the mapping is valid"""
        if len(table) != self.size:
            raise ValueError("Invalid SBOX mapping")
        
        if not self._is_bijective(table):
            raise ValueError("Invalid SBOX mapping")
        else:
            self.table = table
        
    def _is_bijective(self, table):
        """Check if the mapping is bijective by having a one to one mapping"""
        # check the ranges of the table
        if not all(0 <= i < self.size for i in table):
            return False
        
        # check if the mapping is one to one
        return len(set(table)) == self.size
    
    def _compute_inverse(self) -> None:
        """Compute the inverse of the SBOX"""
        self.inverse = [0] * self.size
        for i, val in enumerate(self.table):
            self.inverse[val] = i

    def _convert_to_int(self, x: list) -> int:
        """Convert a binary list to an integer"""
        # Ensure the input list is the correct length
        if len(x) != self.bits:
            raise ValueError(f"Input must be {self.bits} bits long")
        
        return sum([x[i] << i for i in range(self.bits)])
    
    def _convert_to_binary(self, x: int) -> list:
        """Convert an integer to a binary list"""
        # Return a list of correct length
        return [1 if (x >> i) & 1 else 0 for i in range(self.bits)]

    def encrypt(self, x: list) -> list:
        """Encrypt using the SBOX"""
        x_int = self._convert_to_int(x)
        y = self.table[x_int]
        return self._convert_to_binary(y)
    
    def decrypt(self, x: list) -> list:
        """Decrypt using the SBOX"""
        x_int = self._convert_to_int(x)
        y = self.inverse[x_int]
        return self._convert_to_binary(y)


class SubstitutionLayer(Layer):
    def __init__(self, sboxes: list, length: int):
        """Substitution layer for SPN cipher"""
        self.length = length
        
        # check sboxes are all of SBOX class and have the same size
        if not all(isinstance(sbox, SBOX) for sbox in sboxes):
            raise ValueError("All sboxes must be instances of SBOX class")
        
        sbox_bits = sboxes[0].bits
        if not all(sbox.bits == sbox_bits for sbox in sboxes):
            raise ValueError("All SBOXes must have the same bit size")
        
        # check the length of the sboxes is a multiple of the length
        if self.length != (sbox_bits * len(sboxes)):
            raise ValueError("Invalid SBOX length")
        
        self.sboxes = sboxes
        self.bits = sbox_bits

    def __repr__(self):
        """String representation of the SubstitutionLayer"""
        return "SubstitutionLayer(length={})".format(self.length)

    def encrypt(self, state: list) -> list:
        """Encrypt the state using the SBOXES"""
        if len(state) != self.length:
            raise ValueError("Invalid state length")
        
        result = []
        for i, sbox in enumerate(self.sboxes):
            start_idx = i * self.bits
            chunk = state[start_idx:start_idx + self.bits]
            result.extend(sbox.encrypt(chunk))
        
        return result
    
    def decrypt(self, state: list) -> list:
        """Decrypt the state using the SBOXES"""
        if len(state) != self.length:
            raise ValueError("Invalid state length")
        
        result = []
        for i, sbox in enumerate(self.sboxes):
            start_idx = i * self.bits
            chunk = state[start_idx:start_idx + self.bits]
            result.extend(sbox.decrypt(chunk))
        
        return result


class PermutationLayer(Layer):
    def __init__(self, perm_map: dict=None):
        """Permutation layer for SPN cipher"""
        self.permutation = self._validate_permutation(perm_map)
        self.length = len(self.permutation)

    def _validate_permutation(self, perm_map):
        """Check if the permutation map is valid"""
        if not perm_map:
            raise ValueError("Permutation map cannot be None")
            
        # Check for valid range and unique values
        if not all(0 <= i < len(perm_map) for i in perm_map.values()):
            raise ValueError("Invalid permutation map: values out of range")
        
        if len(set(perm_map.values())) != len(perm_map):
            raise ValueError("Invalid permutation map: duplicate destination positions")
        
        return perm_map
    
    def __repr__(self):
        return "PermutationLayer(length={})".format(self.length)
    
    def encrypt(self, state: list) -> list:
        """Encrypt the state using the permutation map"""
        if len(state) != self.length:
            raise ValueError("Invalid state length")
        
        result = [0] * self.length
        for src, dst in self.permutation.items():
            result[dst] = state[src]
        
        return result
    
    def decrypt(self, state: list) -> list:
        """Decrypt the state using the inverse permutation map"""
        if len(state) != self.length:
            raise ValueError("Invalid state length")
        
        result = [0] * self.length
        for dst, src in self.permutation.items():
            result[dst] = state[src]
        
        return result
    

def key_whitening(state: list, key: list) -> list:
    """Apply key whitening to the state"""
    if len(state) != len(key):
        raise ValueError("Invalid key length")
    
    return [state[i] ^ key[i] for i in range(len(state))]

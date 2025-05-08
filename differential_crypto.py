from spn_components import SBOX, format_state
from spn import SPN, generate_round_key
import numpy as np
import pandas as pd



sbox = SBOX([
                0x7, 0xD, 0xE, 0x3, 0x0, 0x6, 0x9, 0xA, 0x1, 0x2, 0x8, 0x5, 0xB, 0xC, 0x4, 0xF
            ])
perm_map = {
    0: 0, 1: 4, 2: 8, 3: 12, 4: 1, 5: 5, 6: 9, 7: 13, 8: 2, 9: 6, 10: 10, 11: 14, 12: 3, 13: 7, 14: 11, 15: 15
}


# Create the SPN we want to crack
spn = SPN(length=16)
spn.build_standard_spn(sbox, perm_map, generate_round_key)

# Test encryption and decryption
plaintext = [1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0]
master_key = [0,1,1,0, 1,0,1,0, 1,1,0,0, 0,1,0,1, 1,0,0,1, 0,1,1,0, 1,0,1,0, 1,1,0,0]
encrypted = spn.encrypt(plaintext, master_key)
decrypted = spn.decrypt(encrypted, master_key)

print(format_state(plaintext))
print(format_state(encrypted))
print(format_state(decrypted))

assert(decrypted == plaintext)

# Perform differential cryptanalysis by finding the difference in the output of the SBOX

# Create a dataframe to store the results with columns 0-15
df = pd.DataFrame(columns=[i for i in range(16)], dtype=int)
for a_prime in range(16):
    # Generate all possible inputs to the SBOX
    a_all = [i for i in range(16)]
    # for each combination of inputs, get the XOR difference as a_star
    a_star = [a ^ a_prime for a in a_all]

    # Get the output of the SBOX for each input
    b_all = [sbox._convert_to_int(sbox.encrypt(sbox._convert_to_binary(a))) for a in a_all]
    b_star = [sbox._convert_to_int(sbox.encrypt(sbox._convert_to_binary(a))) for a in a_star]

    # Map XOR over both b_all and b_star
    b_diff = [b_all[i] ^ b_star[i] for i in range(16)]

    # Count the number of times each output difference occurs
    diff_counts = np.zeros(16, dtype=int)
    for diff in b_diff:
        diff_counts[diff] += 1

    # Print the result in a pandas dataframe
    # print(f"Input difference: {a_prime}")
    # print(pd.DataFrame({
    #     'a': a_all,
    #     'a*': a_star,
    #     'b': b_all,
    #     'b*': b_star,
    #     "b'": b_diff
    # }))

    # print(f"Output difference counts: {diff_counts}")

    # Add diff_counts as row to the dataframe
    df.loc[a_prime] = diff_counts

# # Print the max value in the dataframe
# print(df)

# # Calculate the maximum value not including the first row and column
# max_val = df.iloc[1:, 1:].max().max()
# print(f"Max value: {max_val}")


def trace_differential_trail(input_diff, num_rounds=4):
    # Convert to 4 S-box format (4 nibbles)
    state_diff = [0, 0, 0, 0]  # Assuming we start with S-box 1 active
    state_diff[1] = input_diff  # Put our difference in the second S-box
    
    trail_probability = 1.0
    active_sboxes = []
    trails = [state_diff]
    
    for round_num in range(num_rounds-1):  # -1 because last round has no permutation
        # Apply S-box differentials
        after_sbox = [0, 0, 0, 0]
        for i in range(4):
            if state_diff[i] != 0:
                # Find the most probable output difference for this input difference
                output_diff = df.loc[state_diff[i]].idxmax()
                probability = df.loc[state_diff[i], output_diff] / 16.0
                trail_probability *= probability
                after_sbox[i] = output_diff
                active_sboxes.append(i)
        
        # Apply permutation
        after_perm = [0, 0, 0, 0]
        for sbox_idx in range(4):
            for bit_idx in range(4):
                # Get the current bit value (make sure it's an integer)
                current_bit = (int(after_sbox[sbox_idx]) >> bit_idx) & 1
                if current_bit:
                    # Calculate source and destination positions
                    bit_pos = sbox_idx * 4 + bit_idx
                    perm_pos = perm_map[bit_pos]
                    new_sbox = perm_pos // 4
                    new_bit = perm_pos % 4
                    # Set the bit in the new position
                    after_perm[new_sbox] |= (1 << new_bit)
        
        state_diff = after_perm
        trails.append(state_diff)
    
    # Last round S-box (no permutation)
    final_diff = [0, 0, 0, 0]
    for i in range(4):
        if state_diff[i] != 0:
            output_diff = df.loc[state_diff[i]].idxmax()
            probability = df.loc[state_diff[i], output_diff] / 16.0
            trail_probability *= probability
            final_diff[i] = output_diff
            active_sboxes.append(i)
    
    trails.append(final_diff)
    
    return {
        'trail': trails,
        'probability': trail_probability,
        'active_sboxes': len(set(active_sboxes))
    }


def find_best_differential_trail():
    best_probability = 0
    best_trail = None
    
    # Try each S-box position with high-probability input differences
    for sbox_pos in range(4):
        # Get top input differences (excluding 0)
        # top_diffs = df.iloc[1:].sum(axis=1).nlargest(5).index.tolist()
        top_diffs = df.iloc[1:].max(axis=1).nlargest(5).index.tolist()
        
        for input_diff in top_diffs:
            # Initialize starting difference pattern
            start_diff = [0, 0, 0, 0]
            start_diff[sbox_pos] = int(input_diff)
            
            result = trace_differential_trail(start_diff)
            
            if result['probability'] > best_probability:
                best_probability = result['probability']
                best_trail = result
    
    return best_trail

def main():
    # Find the best differential trail
    result = find_best_differential_trail()
    print(result)
    
    # Print the best trail
    print("Best differential trail:")
    for i, state in enumerate(result['trail']):
        print(f"Round {i+1}: {format_state(state)}")
    
    print(f"Trail probability: {result['probability']}")
    print(f"Active S-boxes: {result['active_sboxes']}")

if __name__ == '__main__':
    main()

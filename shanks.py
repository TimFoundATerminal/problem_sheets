import math

def shanks_algorithm(alpha, beta, p):

    # Calculate m = ceil(sqrt(p))
    m = math.ceil(math.sqrt(p))
    
    # Precompute baby steps: {alpha^j : j ∈ [0, m)}
    baby_steps = {}
    for j in range(m):
        baby_steps[pow(alpha, j, p)] = j
    
    # Compute alpha^(-m) mod p
    alpha_inv = pow(alpha, p - 2, p)  # Using Fermat's little theorem for modular inverse
    alpha_to_minus_m = pow(alpha_inv, m, p)
    
    # Compute giant steps: {beta * (alpha^(-m))^i : i ∈ [0, m)}
    current = beta
    for i in range(m):
        # Check if this giant step matches any baby step
        if current in baby_steps:
            # Found a match: x = i*m + j
            return i * m + baby_steps[current]
        
        # Move to next giant step
        current = (current * alpha_to_minus_m) % p
    
    # No solution found
    return None

# Example usage
def example():
    p = 809  # Prime modulus
    alpha = 3  # Generator
    beta = 525  # Target
    
    result = shanks_algorithm(alpha, beta, p)
    if result is not None:
        print(f"Log_{alpha}({beta}) mod {p} = {result}")
        print(f"Verification: {alpha}^{result} mod {p} = {pow(alpha, result, p)}")
    else:
        print(f"No solution exists for {alpha}^x ≡ {beta} (mod {p})")

if __name__ == "__main__":
    example()
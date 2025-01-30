import os, hashlib

# Safe prime and an integer group
Q_hex = (
    "ff2cfb1ea9971d05eaba56e247cbb60e7b0ccedb0226d74cc07b325df361f227e5280a8c5934cd2b6b1ad3fbb098288ed2908c7b03ec621c9c312fa85301e809"
)
group_Q = int(Q_hex, 16)
group_p = (group_Q - 1) // 2
generator = 2

def Hash(msg: bytes) -> bytes:
    # Hash a message into a 1024-bit string
    H = hashlib.sha3_512
    return H(msg).digest()


def GroupPower(group_element, exponent):
    try:
        return pow(group_element, exponent, group_Q)
    except:
        return 0
    
def HashtoInt(salt, username, password):
    # Input:
    #   salt: bytes
    #   username: string
    #   password: string
    # Output:
    #   H(pw): bytes
    username_byte = bytes(username, 'utf-8')
    pw_byte = bytes(password, 'utf-8')

    # Attach all bytes
    input = b''
    input += salt
    input += username_byte
    input += pw_byte

    hpw = Hash(input)
    hpw_int = int.from_bytes(hpw)
    return hpw_int % group_Q

def main():




    # Usage sample
    sample_salt = b'sample'
    sample_username = "sample"
    sample_pw = "sample"
    sample_hpw = HashtoInt(sample_salt, sample_username, sample_pw)
    sample_v = GroupPower(generator, sample_hpw)
    print(f"The sample password file is stored in the following format: (username = {sample_username}, salt = {sample_salt}, v = {sample_v})\n\n")



    # Pre-computation attack: The target
    target_salt = b'9\x80\xc9\xef\xd6\x82\xf3\xb1\xf2=V(\x92\xe9\x18\xe8'
    target_username = "RunzhiZeng"
    # target_pw = ...   It is your task to recover it           
    # target_hpw = HashtoInt(target_salt, target_username, target_pw)



    # Stage 1: You know the salt and the username, so you construct a precomputation table




    # Stage 2: Now the password file is leaked. Try to recover the password "immediately" using the precomputational table
    print("Precomputation finished.\n")
    target_v = 10907077764141224676643339349764567605464293624147899526492720550497189292414621232262958616861757404737160031183844777534934310677244113932492705745232271
    print(f"The target password file is: (username = {target_username}, salt = {target_salt}, v = {target_v})")

    # Your code

    print("The target password is:")

    # Check your answer
    filename = "Answer.txt"
    with open(filename, "r") as f:
        answer = f.readline()  # read one line as a string
    print("The answer is:", answer)
    answer_hpw = HashtoInt(target_salt, target_username, answer)
    answer_v = GroupPower(generator, answer_hpw)
    assert target_v == answer_v


if __name__ == "__main__":
    main()

from zk_merkle_tree import get_proof, verify_proof


def test(q):
    problem = [1, 2, 3, 6, 6, 6, 12]
    assignment = [1, 1, 1, -1, -1, -1, 1]
    proof = get_proof(problem, assignment, q)
    print(proof)
    return verify_proof(problem, proof)


if __name__ == '__main__':
    print(test(1))

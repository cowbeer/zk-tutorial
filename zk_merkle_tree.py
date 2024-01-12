import hashlib
import random
from math import log2, ceil


def hash_string(s):
    return hashlib.sha256(s.encode()).hexdigest()


def get_witness(problem, assignment):
    sum = 0
    mx = 0
    side_obfuscator = 1 - 2 * random.randint(0, 1)
    witness = [sum]
    assert len(problem) == len(assignment)
    for num, side in zip(problem, assignment):
        assert side == 1 or side == -1
        sum += side * num * side_obfuscator
        witness += [sum]
        mx = max(mx, num)
    assert sum == 0
    shift = random.randint(0, mx)
    witness = [x + shift for x in witness]
    return witness


def verify_merkle_path(root, data_size, value_id, value, path):
    cur = hash_string(str(value))
    tree_node_id = value_id + int(2 ** ceil(log2(data_size)))
    for sibling in path:
        assert tree_node_id > 1
        if tree_node_id % 2 == 0:
            cur = hash_string(cur + sibling)
        else:
            cur = hash_string(sibling + cur)
        tree_node_id = tree_node_id // 2
    assert tree_node_id == 1
    return root == cur


def get_proof(problem, assignment, num_queries):
    proof = []
    randomness_seed = problem[:]
    for i in range(num_queries):
        witness = get_witness(problem, assignment)
        tree = ZkMerkleTree(witness)
        random.seed(str(randomness_seed))
        query_index = random.randint(0, len(problem))
        query_and_response = [tree.get_root()]
        query_and_response += [query_index]
        query_and_response += tree.get_val_and_path(query_index)
        query_and_response += tree.get_val_and_path((query_index + 1) % len(witness))
        proof += [query_and_response]
        randomness_seed += [query_and_response]
    return proof


def verify_proof(problem, proof):
    proof_checks_out = True
    randomness_seed = problem[:]
    for query in proof:
        random.seed(str(randomness_seed))
        query_index = random.randint(0, len(problem))
        merkle_root = query[0]
        proof_checks_out &= query_index == query[1]
        if query_index < len(problem):
            proof_checks_out &= abs(query[2] - query[4]) == abs(problem[query_index])
        else:
            proof_checks_out &= query[2] == query[4]
        proof_checks_out &= verify_zk_merkle_path(merkle_root, len(problem) + 1, query_index, query[2], query[3])
        proof_checks_out &= verify_zk_merkle_path(merkle_root, len(problem) + 1, (query_index + 1) % (len(problem) + 1),
                                                  query[4], query[5])
        randomness_seed += [query]
    return proof_checks_out


# 验证auth path
def verify_zk_merkle_path(root, data_size, id, value, path):
    cur = hash_string(str(value))
    tree_node_id = id * 2 + int(2 ** ceil(log2(data_size * 2)))
    for sibling in path:
        assert tree_node_id > 1
        if tree_node_id % 2 == 0:
            cur = hash_string(cur + sibling)
        else:
            cur = hash_string(sibling + cur)
        tree_node_id = tree_node_id // 2
    assert tree_node_id == 1
    return root == cur


class MerkleTree:
    def __init__(self, data):
        self.data = data
        next_pow_of_2 = int(2 ** ceil(log2(len(data))))
        self.data.extend([0] * (next_pow_of_2 - len(data)))
        self.tree = ["" for x in self.data] + [hash_string(str(x)) for x in self.data]
        for i in range(len(self.data) - 1, 0, -1):
            self.tree[i] = hash_string(self.tree[i * 2] + self.tree[i * 2 + 1])

    def get_root(self):
        return self.tree[1]

    def get_val_and_path(self, id):
        val = self.data[id]
        auth_path = []
        id = id + len(self.data)
        while id > 1:
            auth_path += [self.tree[id ^ 1]]
            id = id // 2
        return val, auth_path


class ZkMerkleTree:
    def __init__(self, data):
        self.data = data
        # 计算满二叉树层数(向上取整)
        next_power_of_2 = int(2 ** ceil(log2(len(data))))
        # 扩展数组,保证能存放满二叉树
        self.data.extend([0] * (next_power_of_2 - len(data)))
        # 产生随机数列表
        random_list = [random.randint(0, 1 << 32) for x in self.data]
        #
        self.data = [x for tup in zip(self.data, random_list) for x in tup]
        #
        self.tree = ["" for x in self.data] + [hash_string(str(x)) for x in self.data]
        # 构造二叉树
        for i in range(len(self.data) - 1, 0, -1):
            self.tree[i] = hash_string(self.tree[i * 2] + self.tree[i * 2 + 1])

    # 返回树根
    def get_root(self):
        return self.tree[1]

    # 返回某个节点的auth path
    def get_val_and_path(self, index):
        index = index * 2
        val = self.data[index]
        index = index + len(self.data)
        auth_path = []
        while index > 1:
            auth_path += [self.tree[index ^ 1]]
            index = index // 2
        return val, auth_path
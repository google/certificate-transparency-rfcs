from random import getrandbits
from hashlib import sha256
from struct import pack

##########################################################################################
# Class used to represent a Merkle tree used by test below
##########################################################################################
class MerkleTree:
  def __init__(self, size):
    self.entries = []
    for idx in range(size):
      self.entries.append(pack('!Q', getrandbits(64)))
    self.cache = {}

  def calc_mth(self, start, end):
    k = '%i-%i' % (start, end)
    rv = self.cache.get(k, None)
    if not rv:
      stack = []
      tree_size = end - start
      for idx, leaf in enumerate(self.entries[start:end]):
        stack.append(sha256(chr(0) + leaf).digest())
        for _ in range(bin(idx).replace('b', '')[::-1].index('0') if idx + 1 < tree_size else len(stack) - 1):
          stack[-2:] = [sha256(chr(1) + stack[-2] + stack[-1]).digest()]
      rv = stack[0]
      self.cache[k] = rv
    return rv

  # From RFC
  def subproof(self, m, start_n, end_n, b):
    n = end_n - start_n
    if m == n:
      if b:
        return []
      else:
        return [(start_n, end_n)]
    else:
      k = 1 << (len(bin(n - 1)) - 3)
      if m <= k:
        return self.subproof(m, start_n, start_n + k, b) + [(start_n + k, end_n)]
      else:
        return self.subproof(m - k, start_n + k, end_n, False) + [(start_n, start_n + k)]

  # From RFC
  def proof(self, first, second):
    return [self.calc_mth(a, b) for a, b in self.subproof(first, 0, second, True)]

  # From RFC
  def path(self, m, start_n, end_n):
    n = end_n - start_n
    if n == 1:
      return []
    else:
      k = 1 << (len(bin(n - 1)) - 3)
      if m < k:
        return self.path(m, start_n, start_n + k) + [(start_n + k, end_n)]
      else:
        return self.path(m - k, start_n + k, end_n) + [(start_n, start_n + k)]

  # Inclusion proof
  def inclusion_proof(self, m, n):
    return [self.calc_mth(a, b) for a, b in self.path(m, 0, n)]

##########################################################################################
# The following are utility methods used by the reference implementations below
##########################################################################################
def is_pow2(x):
  z = x
  while (z & 1) == 0:
    z >>= 1
  return z == 1

def lsb(x):
  return x & 1

##########################################################################################
# The following algorithms are implemented as specified in the RFC
##########################################################################################
def calc_mth_via_rfc_algorithm(entries, tree_size):
  #  1.  Set "stack" to an empty stack.
  stack = []

  # 2.  For each "i" from "0" up to "tree_size - 1":
  for i in range(tree_size):
    #  1.  Push "HASH(0x00 || entries[i])" to "stack".
    stack.append(sha256(chr(0) + entries[i]).digest())

    #   2.  Set "merge_count" to the lowest value ("0" included) such
    #       that "LSB(i >> merge_count)" is not set.  In other words, set
    #       "merge_count" to the number of consecutive "1"s found
    #       starting at the least significant bit of "i".
    merge_count = 0
    while lsb(i >> merge_count):
      merge_count += 1

    #   3.  Repeat "merge_count" times:
    for j in range(merge_count):
      #       1.  Pop "right" from "stack".
      right = stack.pop()
      #       2.  Pop "left" from "stack".
      left = stack.pop()
      #      3.  Push "HASH(0x01 || left || right)" to "stack".
      stack.append(sha256(chr(1) + left + right).digest())

  #3.  If there is more than one element in the "stack", repeat the same
  #    merge procedure (Step 2.3 above) until only a single element
  #    remains.
  while len(stack) > 1:
    #       1.  Pop "right" from "stack".
    right = stack.pop()
    #       2.  Pop "left" from "stack".
    left = stack.pop()
    #      3.  Push "HASH(0x01 || left || right)" to "stack".
    stack.append(sha256(chr(1) + left + right).digest())

  #4.  The remaining element in "stack" is the Merkle Tree hash for the
  #    given "tree_size" and should be compared by equality against the
  #    supplied "root_hash".
  return stack[0]


def check_consistency_via_rfc_algorithm(first, second, first_hash, second_hash, consistency):
  #1.  If "first" is an exact power of 2, then prepend "first_hash" to
  #      the "consistency" array.
  if is_pow2(first):
    consistency = [first_hash] + consistency

  # 2.  Set "fn" to "first - 1" and "sn" to "second - 1".
  fn, sn = first - 1, second - 1

  # 3.  If "LSB(fn)" is set, then right-shift both "fn" and "sn" equally
  #     until "LSB(fn)" is not set.
  while lsb(fn): fn, sn = fn >> 1, sn >> 1

  # 4.  Set both "fr" and "sr" to the first value in the "consistency"
  #     array.
  if len(consistency) == 0:
    return False
  fr = sr = consistency[0]

  # 5.  For each subsequent value "c" in the "consistency" array:
  for c in consistency[1:]:
    if sn == 0:
      return False
    #   If "LSB(fn)" is set, or if "fn" is equal to "sn", then:
    if lsb(fn) or (fn == sn):
      # 1.  Set "fr" to "HASH(0x01 || c || fr)"
      #     Set "sr" to "HASH(0x01 || c || sr)"
      fr, sr = sha256(chr(1) + c + fr).digest(), sha256(chr(1) + c + sr).digest()

      # 2.  If "LSB(fn)" is not set, then right-shift both "fn" and "sn"
      #     equally until either "LSB(fn)" is set or "fn" is "0".
      while not ((fn == 0) or lsb(fn)): fn, sn = fn >> 1, sn >> 1
    #   Otherwise:
    else:
      #    Set "sr" to "HASH(0x01 || sr || c)"
      sr = sha256(chr(1) + sr + c).digest()

    # Finally, right-shift both "fn" and "sn" one time.
    fn, sn = fn >> 1, sn >> 1

  # 6.  After completing iterating through the "consistency" array as
  #     described above, verify that the "fr" calculated is equal to the
  #     "first_hash" supplied and that the "sr" calculated is equal to
  #     the "second_hash" supplied.
  return fr == first_hash and sr == second_hash and sn == 0


def check_inclusion_via_rfc_algorithm(hash, leaf_index, audit_path, tree_size, root_hash):
  # 1.  Compare "leaf_index" against "tree_size".  If "leaf_index" is
  #     greater than or equal to "tree_size" fail the proof verification.
  if leaf_index >= tree_size or leaf_index < 0:
    return False

  # 2.  Set "fn" to "leaf_index" and "sn" to "tree_size - 1".
  fn, sn = leaf_index, tree_size - 1

  # 3.  Set "r" to "hash".
  r = hash

  # 4.  For each value "p" in the "audit_path" array:
  for p in audit_path:
     #  If "LSB(fn)" is set, or if "fn" is equal to "sn", then:
    if lsb(fn) or (fn == sn):
      # 1.  Set "r" to "HASH(0x01 || p || r)"
      r = sha256(chr(1) + p + r).digest()

      # 2.  If "LSB(fn)" is not set, then right-shift both "fn" and "sn"
      #     equally until either "LSB(fn)" is set or "fn" is "fn".
      while not ((fn == 0) or lsb(fn)):
        fn >>= 1
        sn >>= 1
    # Otherwise:
    else:
      #    Set "r" to "HASH(0x01 || r || p)"
      r = sha256(chr(1) + r + p).digest()
    #   Finally, right-shift both "fn" and "sn" one time.
    fn >>= 1
    sn >>= 1

  # 5.  Compare "sn" to 0.  Compare "r" against the "root_hash".  If "sn"
  #     is equal to 0, and "r" and the "root_hash" are equal, then the
  #     log has proven the inclusion of "hash".  Otherwise, fail the
  #     proof verification.
  return sn == 0 and r == root_hash


##########################################################################################
# The following algorithm is specified in the DNS RFC and tested here
##########################################################################################
def audit_path_length(index, tree_size):
  length = 0
  ln = tree_size - 1
  li = index
  while ln:
    if li & 1 or li < ln:
      length += 1
    li >>= 1
    ln >>= 1
  return length

##########################################################################################
# The following are extracted from https://github.com/google/certificate-transparency
# and are used to cross-check the algorithms in the RFC.
##########################################################################################
def cross_check_consistency_against_opensource_algorithm(first, second, first_hash, second_hash, consistency):
  try:
    node = first - 1
    last_node = second - 1

    while node & 1:
      node >>= 1
      last_node >>= 1

    p = iter(consistency)
    if node:
      old_hash = p.next()
    else: # old was 2 ** n
      old_hash = first_hash
    new_hash = old_hash

    while node:
      if node & 1:
        x = p.next()
        old_hash = sha256(chr(1) + x + old_hash).digest()
        new_hash = sha256(chr(1) + x + new_hash).digest()
      elif node < last_node:
        new_hash = sha256(chr(1) + new_hash + p.next()).digest()
      node >>= 1
      last_node >>= 1
    while last_node:
      new_hash = sha256(chr(1) + new_hash + p.next()).digest()
      last_node >>= 1

    for remaining in p:
      return False # we shouldn't have any elements left over

    return old_hash == first_hash and new_hash == second_hash
  except StopIteration:
    return False # ran out of elements


def cross_check_inclusion_via_opensource(hash, leaf_index, audit_path, tree_size, root_hash):
  path_root_hash = opensource_root_from_path(leaf_index, tree_size, audit_path, hash)
  if not path_root_hash:
    return False
  return path_root_hash == root_hash

def opensource_root_from_path(leaf_index, tree_size, audit_path, hash):
  if leaf_index >= tree_size or leaf_index < 0:
    return ""

  node_index = leaf_index
  last_node = tree_size - 1

  calculated_hash = hash
  audit_path = audit_path[:]

  while last_node:
    if not audit_path:
      return ""

    if node_index % 2:
      audit_hash = audit_path.pop(0)
      calculated_hash = sha256(chr(1) + audit_hash + calculated_hash).digest()
    elif node_index < last_node:
      audit_hash = audit_path.pop(0)
      calculated_hash = sha256(chr(1) + calculated_hash + audit_hash).digest()
    # node_index == last_node and node_index is even: A sibling does
    # not exist. Go further up the tree until node_index is odd so
    # calculated_hash will be used as the right-hand operand.
    node_index //= 2
    last_node //= 2
  if audit_path:
      return ""

  return calculated_hash


##########################################################################################
# Test algorithms on a Merkle tree with random data, if no exceptions are raised, we are good!
##########################################################################################
size = 300
t = MerkleTree(size)
t2 = MerkleTree(size)

def check_inclusion(hash, leaf_index, audit_path, tree_size, root_hash):
  r1 = check_inclusion_via_rfc_algorithm(hash, leaf_index, audit_path,
                                         tree_size, root_hash)
  r2 = cross_check_inclusion_via_opensource(hash, leaf_index, audit_path,
                                            tree_size, root_hash)
  assert r1 == r2
  return r1

inclusion_tests_fail = [
  {"leaf_index": 0, "tree_size": 0, "path": [], "root_hash": "", "leaf": ""},
  {"leaf_index": 0, "tree_size": 1, "path": [], "root_hash": "", "leaf": ""},
  {"leaf_index": 1, "tree_size": 0, "path": [], "root_hash": "", "leaf": ""},
  {"leaf_index": 2, "tree_size": 1, "path": [], "root_hash": "", "leaf": ""},
  {"leaf_index": 0, "tree_size": 0, "path": [], "root_hash": sha256("").digest(), "leaf": ""},
  {"leaf_index": 1, "tree_size": 1, "path": [], "root_hash": sha256("").digest(), "leaf": ""},
  {"leaf_index": 2, "tree_size": 1, "path": [], "root_hash": sha256("").digest(), "leaf": ""},
]

def check_inclusion_tests_fail(tests):
  for test in tests:
    print 'Checking inclusion proof for leaf {!s}, tree_size {!s}...'.format(test["leaf_index"], test["tree_size"]),
    assert not check_inclusion(sha256(test["leaf"]).digest(),
                               test["leaf_index"], test["path"],
                               test["tree_size"], test["root_hash"])
    print 'SUCCESS.'

check_inclusion_tests_fail(inclusion_tests_fail)

def check_inclusion_thorough(hash, leaf_index, audit_path, tree_size, root_hash):
  assert check_inclusion(hash, leaf_index, audit_path, tree_size, root_hash)

  # Wrong leaf index
  assert not check_inclusion(hash, leaf_index - 1, audit_path, tree_size, root_hash)
  assert not check_inclusion(hash, leaf_index + 1, audit_path, tree_size, root_hash)

  # Wrong tree height
  assert not check_inclusion(hash, leaf_index, audit_path, tree_size * 2, root_hash)
  assert not check_inclusion(hash, leaf_index, audit_path, tree_size / 2, root_hash)

  # Wrong leaf
  assert not check_inclusion(sha256("WrongLeaf").digest(), leaf_index, audit_path, tree_size, root_hash)

  # Wrong paths
  # Modify a single element on the path
  for i in range(0, len(audit_path)):
    wrong_path = audit_path[:]
    wrong_path[i] = sha256("").digest()
    assert not check_inclusion(hash, leaf_index, wrong_path, tree_size, root_hash)

  # Add garbage at the end of the path
  wrong_path = audit_path[:]
  wrong_path.append("")
  assert not check_inclusion(hash, leaf_index, wrong_path, tree_size, root_hash)
  wrong_path.pop()

  wrong_path.append(root_hash)
  assert not check_inclusion(hash, leaf_index, wrong_path, tree_size, root_hash)
  wrong_path.pop()

  # Remove the node from the end
  if wrong_path:
    wrong_path.pop()
    assert not check_inclusion(hash, leaf_index, wrong_path, tree_size, root_hash)

  # Add garbage to the beginning of the path
  wrong_path = [""] + audit_path
  assert not check_inclusion(hash, leaf_index, wrong_path, tree_size, root_hash)
  wrong_path[0] = root_hash
  assert not check_inclusion(hash, leaf_index, wrong_path, tree_size, root_hash)

for tree_size in range(1, size + 1):
  root_hash = t.calc_mth(0, tree_size)
  print 'Checking calculation of MTH for size %s...' % tree_size,
  assert calc_mth_via_rfc_algorithm(t.entries, tree_size) == root_hash
  assert calc_mth_via_rfc_algorithm(t2.entries, tree_size) != root_hash
  print 'SUCCESS.'

for tree_size in range(1, size + 1):
  root_hash = t.calc_mth(0, tree_size)
  print 'Checking inclusion proofs to %i...' % tree_size,
  for leaf_index in range(0, tree_size):
    apl = audit_path_length(leaf_index, tree_size)
    audit_path = t.inclusion_proof(leaf_index, tree_size)
    assert apl == len(audit_path)
    hash = sha256(chr(0) + t.entries[leaf_index]).digest()

    check_inclusion_thorough(hash, leaf_index, audit_path, tree_size, root_hash)

    audit_path = t2.inclusion_proof(leaf_index, tree_size)
    assert audit_path_length(leaf_index, tree_size) == len(audit_path)
    assert len(audit_path) ^ check_inclusion(hash, leaf_index, audit_path, tree_size,
                               root_hash)
    audit_path = t.inclusion_proof(leaf_index, tree_size) + t.inclusion_proof(leaf_index, tree_size)
    assert len(audit_path) ^ check_inclusion(hash, leaf_index, audit_path, tree_size, root_hash)

    audit_path = t.inclusion_proof(leaf_index, tree_size)[:-1]
    if apl:
      assert not check_inclusion(hash, leaf_index, audit_path, tree_size, root_hash)

  print 'SUCCESS.'

def check_consistency(first, second, first_hash, consistency, second_hash):
  # Wrong indices.
  bad_heights = (
      (first - 1, second), (first + 1, second), (first ^ 2, second),
      (first, second * 2), (first, second / 2))

  for (bad_first, bad_second) in bad_heights:
    if bad_first <= 0 or bad_second <= 0:
      # The RFC proof does not deal with this edge cases (should it?)
      continue
    rfc_res = check_consistency_via_rfc_algorithm(bad_first, bad_second, first_hash, second_hash, consistency)
    cross_check_res = cross_check_consistency_against_opensource_algorithm(bad_first, bad_second, first_hash, second_hash, consistency)
    assert rfc_res == cross_check_res, "reference algorithm result does not match implementation for %d (old rood=%d)" % (bad_first, first)
    assert not rfc_res, "Expected failure for %d (old rood=%d)" % (bad_first, first)

  # Good values
  rfc_res = check_consistency_via_rfc_algorithm(first, second, first_hash, second_hash, consistency)
  cross_check_res = cross_check_consistency_against_opensource_algorithm(first, second, first_hash, second_hash, consistency)
  assert rfc_res == cross_check_res
  return rfc_res

for first in range(1, size - 1):
  first_hash = t.calc_mth(0, first)
  print 'Checking consistency proofs from %i...' % first,
  for second in range(first + 1, size):
    second_hash = t.calc_mth(0, second)

    consistency = t.proof(first, second)
    assert check_consistency(first, second, first_hash, consistency,
                             second_hash)

    consistency = t2.proof(first, second)
    assert not check_consistency(first, second, first_hash, consistency,
                                 second_hash)

    consistency = t.proof(first, second) + t.proof(first, second)
    assert not check_consistency(first, second, first_hash, consistency,
                                 second_hash)

    consistency = t.proof(first, second)[:-1]

    if is_pow2(first): # no point checking first:
      assert not check_consistency(first, second, first_hash, consistency,
                                   second_hash)
    else: # pass random value for first hash since we shouldn't need it
      assert not check_consistency_via_rfc_algorithm(first, second, pack('!Q', getrandbits(64)), second_hash, consistency)
      assert not cross_check_consistency_against_opensource_algorithm(first, second, pack('!Q', getrandbits(64)), second_hash, consistency)

  print 'SUCCESS.'

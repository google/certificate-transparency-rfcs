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
def calc_mth_via_rfc_algorithm(entries, tree_size, sha256_root_hash):
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
   #    supplied "sha256_root_hash".
  if stack[0] != sha256_root_hash:
    raise


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
  fr = sr = consistency[0]

  # 5.  For each subsequent value "c" in the "consistency" array:
  for c in consistency[1:]:
    #   If "LSB(fn)" is set, or if "fn" is equal to "sn", then:
    if lsb(fn) or (fn == sn):
      # 1.  Set "fr" to "HASH(0x01 || c || fr)"
      #     Set "sr" to "HASH(0x01 || c || sr)"
      fr, sr = sha256(chr(1) + c + fr).digest(), sha256(chr(1) + c + sr).digest()

      # 2.  If "LSB(fn)" is not set, then right-shift both "fn" and "sn"
      #     equally until "LSB(fn)" is set.
      while not lsb(fn): fn, sn = fn >> 1, sn >> 1
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
  if fr != first_hash or sr != second_hash:
    raise


def check_inclusion_via_rfc_algorithm(hash, leaf_index, audit_path, sha256_root_hash, tree_size):
  # 1.  Set "fn" to "leaf_index" and "sn" to "tree_size - 1".
  fn, sn = leaf_index, tree_size - 1

  # 2.  Set "r" to "hash".
  r = hash

  # 3.  For each value "p" in the "audit_path" array:
  for p in audit_path:
     #  If "LSB(fn)" is set, or if "fn" is equal to "sn", then:
    if lsb(fn) or (fn == sn):
      # 1.  Set "r" to "HASH(0x01 || p || r)"
      r = sha256(chr(1) + p + r).digest()

      # 2.  If "LSB(fn)" is not set, then right-shift both "fn" and "sn"
      #     equally until "LSB(fn)" is set.
      while not lsb(fn):
        fn >>= 1
        sn >>= 1
    # Otherwise:
    else:
      #    Set "r" to "HASH(0x01 || r || p)"
      r = sha256(chr(1) + r + p).digest()
    #   Finally, right-shift both "fn" and "sn" one time.
    fn >>= 1
    sn >>= 1

  # 4.  Compare "r" against the "sha256_root_hash".  If they are equal,
  #     then the log has proven the inclusion of "hash".
  if r != sha256_root_hash:
    raise

##########################################################################################
# The following are extracted from https://github.com/google/certificate-transparency
# and are used to cross-check the algorithms in the RFC.
##########################################################################################
def cross_check_consistency_against_opensource_algorithm(first, second, first_hash, second_hash, consistency):
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

  if first_hash != old_hash or second_hash != new_hash:
    raise


def cross_check_inclusion_via_opensource(hash, leaf_index, audit_path, sha256_root_hash, tree_size):
  audit_path = audit_path[:]

  node_index = leaf_index
  calculated_hash = hash
  last_node = tree_size - 1
  while last_node > 0:
      if not audit_path:
          raise ('Proof too short: left with node index '
                                 '%d' % node_index)
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
      raise ('Proof too long: Left with %d hashes.' %
                             len(audit_path))

  if calculated_hash != sha256_root_hash:
      raise


##########################################################################################
# Test algorithms on a Merkle tree with random data, if no exceptions are raised, we are good!
##########################################################################################
size = 130
t = MerkleTree(size)

count = 0
for tree_size in range(1, size + 1):
  sha256_root_hash = t.calc_mth(0, tree_size)
  print 'Checking calculation of MTH for size %s...' % tree_size
  calc_mth_via_rfc_algorithm(t.entries, tree_size, sha256_root_hash)
  count += 1

for tree_size in range(1, size + 1):
  sha256_root_hash = t.calc_mth(0, tree_size)
  for leaf_index in range(0, tree_size - 1):
    print 'Checking inclusion proof of %i to %i...' % (leaf_index, tree_size)
    audit_path = t.inclusion_proof(leaf_index, tree_size)
    hash = sha256(chr(0) + t.entries[leaf_index]).digest()
    check_inclusion_via_rfc_algorithm(hash, leaf_index, audit_path, sha256_root_hash, tree_size)
    count += 1
    cross_check_inclusion_via_opensource(hash, leaf_index, audit_path, sha256_root_hash, tree_size)

for first in range(1, size - 1):
  first_hash = t.calc_mth(0, first)
  for second in range(first + 1, size):
    print 'Checking consistency proof of %i to %i...' % (first, second)
    second_hash = t.calc_mth(0, second)
    consistency = t.proof(first, second)

    check_consistency_via_rfc_algorithm(first, second, first_hash, second_hash, consistency)
    count += 1
    cross_check_consistency_against_opensource_algorithm(first, second, first_hash, second_hash, consistency)

print '%i tests successful.' % count
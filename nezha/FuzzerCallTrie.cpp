#include <iostream>
#include <string>
#include <vector>
#include <stdint.h>
#include <stdio.h>
#include <algorithm>
#include <list>
#include <set>

namespace fuzzer {
/*
 *
 * Root cause analysis:
 *
 * For each library, we only need to store two tries: one for successful parses
 * and one for errors. Whenever we have a descrepancy, we look into the opposite
 * trie for a diff: If the library had a 0, we compare with the error trie
 * and if it had an ERR with the 0 trie.
 *
 */


struct Node
{
  std::vector<Node> children;
  uint64_t value;
};

class FuzzerCallTrie
{
  public:

    FuzzerCallTrie(uint64_t root_v);
    FuzzerCallTrie *AddPCTrace(FuzzerCallTrie *t,
                               uint64_t *seq,
                               uint64_t seq_sz,
                               int64_t *diff_idx);
    int64_t GetDiffIdx(FuzzerCallTrie *t,
                       uint64_t *seq,
                       uint64_t seq_sz);
    Node root_node;
};

FuzzerCallTrie::FuzzerCallTrie(uint64_t root_v) {
  root_node.value = root_v;
}

int64_t FuzzerCallTrie::GetDiffIdx(FuzzerCallTrie *t,
                                   uint64_t *seq,
                                   uint64_t seq_sz) {
  uint64_t i;
  bool found;

  // initialize diff index --> -1 means no diff
  int64_t diff_idx = -1;

  if (seq && seq[0] != root_node.value) {
    t = new FuzzerCallTrie(seq[0]);
  }

  std::vector<Node> *node_children = &t->root_node.children;
  for (i = 1; i < seq_sz; i++) {
    Node *n = new Node();
    n->value = seq[i];

    // if this node has no children, then we append the new
    // element as a child and continue. Set diff_idx accordingly
    if (node_children->empty()) {
      if (diff_idx == -1)
        return i - 1;
    } else {
      // the node has children. Look to see if we are already in
      // otherwise, append ourselves as a child and start a new sub-tree
      found = false;
      // if the address is already in the Trie, just continue down
      // the path, without re-appending
      for (std::vector<Node>::iterator it = node_children->begin();
           it != node_children->end();
           it++) {
        if ((*it).value == seq[i]) {
          node_children = &(*it).children;
          found = true;
          break;
        }
      }
      // if it was not found in the children list, just append this node
      if (!found && diff_idx == -1)
        return i - 1;
    }
  }

  return 0;
}

/* diff_idx holds where this seq differs from the existing trie */
FuzzerCallTrie *FuzzerCallTrie::AddPCTrace(FuzzerCallTrie *t,
                                           uint64_t *seq,
                                           uint64_t seq_sz,
                                           int64_t *diff_idx) {
  uint64_t i;
  bool found;

  // initialize diff index --> -1 means no diff
  *diff_idx = -1;

  if (seq && seq[0] != root_node.value) {
    t = new FuzzerCallTrie(seq[0]);
  }

  std::vector<Node> *node_children = &t->root_node.children;
  for (i = 1; i < seq_sz; i++) {
    Node *n = new Node();
    n->value = seq[i];

    // if this node has no children, then we append the new
    // element as a child and continue. Set diff_idx accordingly
    if (node_children->empty()) {
      node_children->push_back(*n);
      if (*diff_idx == -1)
        *diff_idx = i - 1;
    } else {
      // the node has children. Look to see if we are already in
      // otherwise, append ourselves as a child and start a new sub-tree
      found = false;
      // if the address is already in the Trie, just continue down
      // the path, without re-appending
      for (std::vector<Node>::iterator it = node_children->begin();
           it != node_children->end();
           it++) {
        if ((*it).value == seq[i]) {
          node_children = &(*it).children;
          found = true;
          break;
        }
      }
      // if it was not found in the children list, just append this node
      if (!found) {
        node_children->push_back(*n);
        if (*diff_idx == -1)
          *diff_idx = i - 1;
      }
    }
  }

  return t;
}

}

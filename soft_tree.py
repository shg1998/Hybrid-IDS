"""
soft_tree.py - Custom Soft-Label Extension for Streaming Hoeffding Decision Trees
==============================================================================
This module implements a specialized variant of the Hoeffding Tree Classifier 
designed to handle continuous probabilistic targets (soft labels) generated 
via knowledge distillation pipelines.

MATHEMATICAL & ALGORITHMIC PRINCIPLES:
--------------------------------------
Standard streaming Hoeffding Tree implementations (such as River's base class) 
strictly evaluate target parameters as hard-coded categorical values (e.g., y ∈ {0, 1}). 
In high-noise or asymmetric feedback streaming environments, enforcing binary hard labels 
leads to structural instability and volatile splits within the tree nodes.

To preserve the true underlying uncertainty matrix, this custom class overloads the 
`learn_one` method to accept continuous floating-point target variables ($y \in (0, 1)$).

1. Conditional Branching Strategy:
   - Hard Target Flow: If the incoming target `y` is an integer value, it skips 
     probabilistic partitioning and passes directly to the base class routing layer.
   - Soft Target Flow: If `y` is verified as a floating-point probability ($0.0 < y < 1.0$), 
     the algorithm splits the instance into dual training samples.

2. Dual Sample Virtual Mapping Formulation:
   - Instead of assigning a single class label, the algorithm passes the same 
     feature vector `x` to the base class execution loops twice within the same step:
       a) Mapped as Class 1 (Attack) with an adjusted virtual weight: $W_{new} = y \times w$
       b) Mapped as Class 0 (Normal) with an adjusted virtual weight: $W_{new} = (1 - y) \times w$

This dual-weighted update structure forces internal leaf nodes to incrementally 
increment statistics across both output domains relative to the soft signal strength. 
As a result, it acts as a structural regularization barrier that handles n-dimensional 
noise, stabilizes tree growth, and mitigates over-fitting anomalies.
"""

from river import tree

class SoftLabelHoeffdingTree(tree.HoeffdingTreeClassifier):
    def learn_one(self, x, y, *, w=1.0):
        if isinstance(y, float) and 0.0 < y < 1.0:
            super().learn_one(x, 1, w=y * w)
            super().learn_one(x, 0, w=(1 - y) * w)
        else:
            super().learn_one(x, int(y), w=w)

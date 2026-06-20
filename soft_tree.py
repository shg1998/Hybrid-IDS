from river import tree

class SoftLabelHoeffdingTree(tree.HoeffdingTreeClassifier):
    def learn_one(self, x, y, *, w=1.0):
        if isinstance(y, float) and 0.0 < y < 1.0:
            super().learn_one(x, 1, w=y * w)
            super().learn_one(x, 0, w=(1 - y) * w)
        else:
            super().learn_one(x, int(y), w=w)
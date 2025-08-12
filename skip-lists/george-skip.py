# An outline of a skip checkpoint implementation.
#
# Goal: given a trusted checkpoint hash at a height h allow authenticaton 
# of any previous checkpoint with h' < h, with a cost log( h - h'). Optimize 
# parameters for sequences of checkpoints of length about a day (ie. 86400) 
# even assuing a checkpoint a second.


def notch(seq, base=10):
    height = 0
    while seq % base == 0:
        height += 1
        seq = seq // base
        if height > 10:
            return height
    return height

class Checkpoint :
    __slots__ = ("seq", "fingers")

    def __init__(self):
        pass

    def init_initial():
        self = Checkpoint()
        self.seq = 0
        self.fingers = frozenset()
        return self
    
    def init_next(prev_checkpoint):
        self = Checkpoint()
        self.seq = prev_checkpoint.seq + 1
        
        fingers = frozenset([ prev_checkpoint.hash() ]) | prev_checkpoint.fingers
        new_fingers = []
        for (height, seq, hash) in sorted(((notch(seq), seq, hash) for (seq, hash) in fingers) , reverse = True):
            # Always take the highest
            if len(new_fingers) == 0:
                new_fingers.append((height, seq, hash))
            # Then take the next notches
            if new_fingers[-1][0] > height:
                new_fingers.append((height, seq, hash))
        
        self.fingers = frozenset((s, h) for (_, s, h) in new_fingers)
        # print(self.seq, len(self.fingers), [s for (s, _) in self.fingers])
        return self

    def hash(self):
        return (self.seq, self)
    
    def authenticate(self, prev_seq):
        assert 0 <= prev_seq < self.seq
        current_checkpoint = self
        steps = 0
        while current_checkpoint.seq != prev_seq:
            steps += 1
            print(current_checkpoint.seq)
            _, current_checkpoint  = min((seq, hash) for (seq, hash) in current_checkpoint.fingers if seq - prev_seq >= 0)

        return (steps, current_checkpoint)


checkpoints = [Checkpoint.init_initial()]

for i in range(100_000):
    last = checkpoints[-1]
    checkpoints.append(Checkpoint.init_next(last))

print("lookup takes:", checkpoints[-1].authenticate(499))
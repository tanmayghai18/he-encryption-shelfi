import SHELFI_FHE as m
from random import random
import numpy as np
import time

learners = 10
batchSize = 8192
scaleFactorBits = 52
cryptodir = "../resources/cryptoparams/"
ckks = m.Ckks("ckks", learners, batchSize, scaleFactorBits, cryptodir)

print(ckks->learners);


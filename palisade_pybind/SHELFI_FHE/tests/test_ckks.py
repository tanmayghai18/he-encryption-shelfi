import ckks as c
from random import random
import numpy as np
import time

learners = 4
data_dimesions = 9000
scalingFactors = [0.25,0.25,0.25,0.25]
cryptodir = "../resources/cryptoparams/"
batchSize = 8192, scaleFactorBits = 52

ckks = c.ckks(10, batchSize, scaleFactorBits, cryptodir)
ckks.loadCryptoParams()

import sys

sys.path.insert(0, "../build/")

import random
import json

import numpy as np
import SHELFI_FHE as m
from timeit import Timer


class PerformanceStatsAggregator(object):

    def __init__(self):
        self.timings = []
        self.time_mean = None
        self.time_var = None
        self.time_std = None
        self.fn = None
        self.fn_args = None
        self.trials = None

    def run(self, fn, fn_args, trials):
        self.fn = fn
        self.fn_args = fn_args
        self.trials = trials
        timer = Timer(lambda: fn(*fn_args))
        self.timings = []
        for i in range(trials):
            t = timer.timeit(number=1)
            self.timings.append(t)

        self.time_mean = np.mean(self.timings)
        self.time_var = np.var(self.timings)
        self.time_std = np.std(self.timings)

        function_res = fn(*fn_args)
        return function_res

    def to_json(self):
        json_res = {
            "function_name": self.fn.__name__,
            "timings": self.timings,
            "timings_mean": self.time_mean,
            "timings_variance": self.time_var,
            "timings_std": self.time_std,
        }
        return json_res


class PseudoFHEFederationWrapper(object):

    @classmethod
    def get_scaling_probabilities(cls, num_probs):
        """
        Generate the scaling factors / contribution value of each learner in the global model.
        :param num_probs: number of probabilities to generate
        :return:
        """
        scalars = [random.randint(1, 100) for _ in range(num_probs)]
        norm_factor = sum(scalars)
        probs = [x / norm_factor for x in scalars]
        return probs

    @classmethod
    def initialize_learners_data(cls, total_learners, total_params):
        """
        Initialize learners random models.
        :param total_learners: number of learners participating in the federation
        :param total_params: size of the model
        :return:
        """
        learners_data = []
        for i in range(total_learners):
            # TODO (hamzahsaleem) does the SHELFI_FHE library support any numpy array size?
            learners_data.append(np.random.rand(int(total_params / 2.0), 2))
        return learners_data

    @classmethod
    def encrypt_learners_data(cls, learners_data, encrypt_fn):
        """
        Encrypt learners local models using the SHELFI_FHE encryption library.
        :param learners_data: collection of learners models
        :param encrypt_fn: reference to the encryption function
        :return:
        """
        encrypted_learners_data = []
        for d in learners_data:
            encrypted_learners_data.append(encrypt_fn(d))
        return encrypted_learners_data

    @classmethod
    def compute_weighted_average_plain(cls, learners_data, probabilities):
        """
        Vanilla computation of weighted aggregation.
        :param learners_data: collection of non-encrypted learners models
        :param probabilities: contribution value of each learner in the federation
        :return:
        """
        result = []
        for i in range(len(learners_data)):
            result.append((learners_data[i] * probabilities[i]))

        aggregated = result[0]
        for i in range(len(result) - 1):
            aggregated += result[i + 1]

        return aggregated.flatten()

    @classmethod
    def verify_equality(cls, pwa_dec, vanilla_agg):
        """
        Validate the results returned by the private weighted and vanilla aggregation.
        :param pwa_dec: result of private weighted aggregation
        :param vanilla_agg: result of vanilla aggregation - no pwa
        :return:
        """
        test_flag = True

        for i in range(len(pwa_dec)):
            a = "{:.2f}".format(pwa_dec[i])
            b = "{:.2f}".format(vanilla_agg[i])

            if a != b:
                test_flag = False
                print("Parameter Value not Equal")
                print("Computed: " + str(pwa_dec[i]) + " " + "Actual: " + str(vanilla_agg[i]))

        if test_flag:
            print("Computed parameters are correct.")
            print("Test passed successfully.")


def main(total_learners, total_params):

    output_filename_str = "performance_test.learners_{}.params_{}.jsonl".format(learners_num, params_num)
    open("../logs/{}".format(output_filename_str), "w+")
    output_filename = open("../logs/{}".format(output_filename_str), "a")

    performance_aggregator = PerformanceStatsAggregator()
    wrapper = PseudoFHEFederationWrapper()
    FHE_helper = m.FHE_Helper("ckks", 8192, 52)
    FHE_helper.load_crypto_params()

    print("Compute learners scaling factors (probabilities).")
    probabilities = performance_aggregator.run(wrapper.get_scaling_probabilities,
                                               [total_learners],
                                               trials=10)
    print(performance_aggregator.to_json())
    print(performance_aggregator.to_json(), file=output_filename)

    print("\n\nInitialize learners data.")
    learners_data = performance_aggregator.run(wrapper.initialize_learners_data,
                                               [total_learners, total_params],
                                               trials=10)
    print(performance_aggregator.to_json())
    print(performance_aggregator.to_json(), file=output_filename)

    print("\n\nEncrypt learners data.")
    learners_data_encrypted = performance_aggregator.run(wrapper.encrypt_learners_data,
                                                         [learners_data, FHE_helper.encrypt],
                                                         trials=10)
    print(performance_aggregator.to_json())
    print(performance_aggregator.to_json(), file=output_filename)

    print("\n\nCompute Private Weighted Aggregation (PWA).")
    pwa_enc = performance_aggregator.run(FHE_helper.computeWeightedAverage,
                                         [learners_data_encrypted, probabilities],
                                         trials=10)
    print(performance_aggregator.to_json())
    print(performance_aggregator.to_json(), file=output_filename)

    print("\n\nDecrypt PWA result.")
    pwa_dec = performance_aggregator.run(FHE_helper.decrypt, [pwa_enc, total_params],
                                         trials=10)
    print(performance_aggregator.to_json())
    print(performance_aggregator.to_json(), file=output_filename)

    print("\n\nCompute vanilla aggregation - no PWA.")
    vanilla_weighted_avg = performance_aggregator.run(wrapper.compute_weighted_average_plain,
                                                      [learners_data, probabilities],
                                                      trials=10)
    print(performance_aggregator.to_json())
    print(performance_aggregator.to_json(), file=output_filename)

    print("\n\nVerify PWA and vanilla aggregation result.")
    wrapper.verify_equality(pwa_dec, vanilla_weighted_avg)

    output_filename.close()


if __name__ == "__main__":
    """
    We test the encryption library for the following range of values:
        total_learners = {10, 100}
        total_parameters = {100000 (100K), 1000000 (1M), 1e7 (10M), 2*1e7 (20M)}
    """
    # Number of parameters need to be an integer value otherwise the encryption library does not work.
    total_learners, total_parameters = [10, 100], [100000, 1000000, int(1e7), int(2*1e7)]
    for learners_num in total_learners:
        for params_num in total_parameters:
            main(total_learners=learners_num, total_params=params_num)

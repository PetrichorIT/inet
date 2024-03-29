#!/usr/bin/env python

import matplotlib.pyplot as plt

for str in [
    "results/connector_traffic.out",
    "results/client_congestion_window_65.out",
    # "results/client_ssthresh_65.out",
    "results/client_congestion_window_66.out",
    # "results/client_ssthresh_66.out",
    # "results/client_congestion_window_67.out",
    # "results/client_ssthresh_67.out",
    ]:
    with open(str) as f:
        raw_data = f.read()
        lines = raw_data.split("\n");
        x = []
        y = []
        for line in lines:
            if line.startswith("#"):
                continue
            split = line.split("=")

            if len(split) != 2:
                continue
            x.append(float(split[0].strip()))
            y.append(float(split[1].strip()))
        plt.plot(x, y)


plt.ylabel('cong_w')
plt.show();

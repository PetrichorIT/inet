#!/usr/bin/env python

import matplotlib.pyplot as plt

with open("results/client_congestion_window.out") as f:
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

with open("results/client_ssthresh.out") as f:
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

with open("results/connector_traffic.out") as f:
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

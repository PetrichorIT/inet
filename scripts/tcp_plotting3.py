#!/usr/bin/env python

import matplotlib.pyplot as plt

for str in [
    "results/connector_drop.out",
    "results/connector_drops_per_sec.out"
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

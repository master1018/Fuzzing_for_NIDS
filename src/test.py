import random

data1 = ["snort3-browser-chrome", "snort3-sql", "snort3-protocol-ftp", "snort3-protocol-tftp", "snort3-protocol-telnet"]

n = 10
m = 66

data3 = ["SIGN_REPEAT", "SIGN_ALGORITHM", "SIGN_OVERLAP", "SIGN_CONFUSE"]


res = []


def number_of_certain_probability(sequence, probability):
    x = random.uniform(0, 1)
    cumulative_probability = 0.0
    for item, item_probability in zip(sequence, probability):
        cumulative_probability += item_probability
        if x < cumulative_probability:
            break
    return item

for i in range(0, 100):
    a = number_of_certain_probability([2, 0, 1, 3, 4], [0.4, 0.2, 0.2, 0.1, 0.1])
    b = random.randint(n, m)
    c = number_of_certain_probability([0, 1, 2, 3], [0.4, 0.3, 0.2, 0.1])
    str_t = "snort " + data1[a] + " " + str(b) + " " + data3[c]
    res.append(str_t)
for c in res:
    print(c)

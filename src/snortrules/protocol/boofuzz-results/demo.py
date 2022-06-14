import sqlite3


filename = "run-2022-06-10T11-04-19.db"
conn = sqlite3.connect(filename)
cursor = conn.cursor()
sql1 = """SELECT timestamp from cases"""
cursor.execute(sql1)
fuzz_case_list = cursor.fetchall()
sql2 = """SELECT test_case_index, type, description, data, timestamp, is_truncated from steps"""
cursor.execute(sql2)
case_msg = cursor.fetchall()
conn.close()
fp = open("/root/github/internet_product_safe_test/snortrules/protocol/boofuzz-results/case_list.txt", "w")


i = 1
num_of_case = len(fuzz_case_list)


for i in range(0, num_of_case):
    fuzz_case_list[i] = list(fuzz_case_list[i])
for i in range(0, len(case_msg)):
    case_msg[i] = list(case_msg[i])

i = 1

#print(fuzz_case_list)
#print(case_msg)
#print(num_of_case)
#print(len(case_msg))

num_of_msg = len(case_msg)

while 1:
    if i + 4 >= num_of_msg or i + 5 >= num_of_msg or i + 8 >= num_of_msg:
        break
    idx = i // 8
    if idx >= num_of_case:
        break
    fuzz_case_list[idx].append(case_msg[i + 4][2])
    fuzz_case_list[idx].append(case_msg[i + 5][3])
    fuzz_case_list[idx].append(case_msg[i + 7][4])
    i = i + 8

for c in fuzz_case_list:
    print(c, file=fp)
fp.close()

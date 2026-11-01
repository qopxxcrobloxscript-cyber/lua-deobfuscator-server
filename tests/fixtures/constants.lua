print(0, 1, -1, 42, -42, 1000000, -1000000, 255, 16384, -16384)
print(0.5, 3.14, -3.14, 1.5, 0.1, 99.99, -0.001, 123.456)
print(2.718281828, 0.0001, 1000.0001, -0.5)
local a, b = 10.5, 2.25
print(a+b, a-b, a*b, a/b)
local big = 999999999
print(big, big+1, -big)
local arr = {1.1, 2.2, 3.3, -4.4}
local sum = 0
for i=1,#arr do sum = sum + arr[i] end
print("sum=", sum)
print(1/3)
print(10 % 3, 10.5 % 3)

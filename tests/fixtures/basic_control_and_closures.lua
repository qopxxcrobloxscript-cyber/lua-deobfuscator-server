local function fib(n)
  if n < 2 then return n end
  return fib(n-1) + fib(n-2)
end

local t = {}
for i=1,5 do t[i] = i*i end

local sum = 0
for i=1,#t do sum = sum + t[i] end

print("fib(10)=", fib(10))
print("sum=", sum)

local closures = {}
for i=1,3 do closures[i] = function() return i end end
print(closures[1](), closures[2](), closures[3]())

local ok = pcall(function() error("boom") end)
print("pcall:", ok)

local a, b = 10, 3
print("ops:", a+b, a-b, a*b, a%b, a^2, a<b, a>b, a==b)

local str = "hello" .. " " .. "world"
print(str)

local g = 0
for i=1,100 do
  if i % 15 == 0 then g = g + 3
  elseif i % 3 == 0 then g = g + 1
  elseif i % 5 == 0 then g = g + 2
  end
end
print("fizzbuzz_sum=", g)

local function makeCounter()
  local n = 0
  return function() n = n + 1; return n end
end
local c1 = makeCounter()
print(c1(), c1(), c1())

local tbl = {10,20,30,"x","y"}
local cnt = 0
for k,v in pairs(tbl) do cnt = cnt + 1 end
print("pairs_count=", cnt)

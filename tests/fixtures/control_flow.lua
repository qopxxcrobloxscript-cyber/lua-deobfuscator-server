-- 分岐・ループ・break相当・ネストを網羅的にテストする
local function classify(n)
  if n < 0 then return "neg"
  elseif n == 0 then return "zero"
  elseif n < 10 then return "small"
  elseif n < 100 then return "medium"
  else return "large"
  end
end
for _,v in ipairs({-5, 0, 3, 50, 1000}) do
  print(v, classify(v))
end

-- while + break相当
local i = 0
local acc = {}
while true do
  i = i + 1
  if i > 10 then break end
  if i % 2 == 0 then acc[#acc+1] = i end
end
print(table.concat(acc, ","))

-- repeat/until
local j = 0
local r = 0
repeat
  j = j + 1
  r = r + j
until j >= 5
print("repeat sum=", r)

-- numeric for with step
local s = 0
for k=10,1,-2 do s = s + k end
print("step sum=", s)

-- nested loops with inner break-like logic
local matrix_sum = 0
for a=1,5 do
  for b=1,5 do
    if a==b then
      matrix_sum = matrix_sum + 1
    elseif a>b then
      matrix_sum = matrix_sum + 2
    end
  end
end
print("matrix_sum=", matrix_sum)

-- generic for (pairs/ipairs) mixed with conditions
local tbl = {10,20,30,40,50}
local evensum = 0
for idx,val in ipairs(tbl) do
  if val % 20 == 0 then evensum = evensum + val end
end
print("evensum=", evensum)

-- deeply nested if inside loop inside function
local function deep(n)
  local total = 0
  for x=1,n do
    if x % 3 == 0 then
      if x % 5 == 0 then
        total = total + 100
      else
        total = total + 10
      end
    elseif x % 2 == 0 then
      total = total + 1
    end
  end
  return total
end
print("deep(30)=", deep(30))

-- and/or short-circuit control flow
local function f1() print("f1called"); return true end
local function f2() print("f2called"); return false end
local r1 = f2() and f1()
local r2 = f2() or f1()
print(r1, r2)

-- pcall with nested error inside loop
local errs = 0
for n=1,5 do
  local ok = pcall(function()
    if n == 3 then error("boom"..n) end
    return n
  end)
  if not ok then errs = errs + 1 end
end
print("errs=", errs)

local function quicksort(arr, lo, hi)
  lo = lo or 1; hi = hi or #arr
  if lo < hi then
    local pivot = arr[hi]
    local i = lo - 1
    for j = lo, hi-1 do
      if arr[j] <= pivot then
        i = i + 1
        arr[i], arr[j] = arr[j], arr[i]
      end
    end
    arr[i+1], arr[hi] = arr[hi], arr[i+1]
    quicksort(arr, lo, i)
    quicksort(arr, i+2, hi)
  end
  return arr
end
local data = {5,3,8,1,9,2,7,4,6,0,33,21,12}
local sorted = quicksort(data)
print(table.concat(sorted, ","))

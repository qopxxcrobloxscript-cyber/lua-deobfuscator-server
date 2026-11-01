print("")
print("a")
print("hello")
print("hello world, this is a longer string to test chunk splitting!")
print("short1")
print("short1")
print("特殊文字と日本語のテスト文字列です、これはチャンク分割されるくらい長いはず")
print("line1\nline2\ttabbed")
print("exactly twenty four chars!!")
print("exactly twenty five chars!!!")
print("quotes \" and 'apostrophe' and backslash \\")
local t = {"dup","dup","dup"}
print(t[1],t[2],t[3])
local long1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
print(#long1, long1)
local name_test = "this_is_a_variable_name_like_string_used_as_a_global_table_key_for_testing"
local g = {}
g[name_test] = 42
print(g[name_test])

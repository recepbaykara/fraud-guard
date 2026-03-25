-- Luacheck Configuration for Fraud Guard Plugin
-- Static code analysis and linting rules

-- Lua version
std = "ngx_lua"

-- Global variables from Kong and OpenResty
globals = {
  "kong",
  "ngx",
}

-- Read-only globals
read_globals = {
  "describe",
  "it",
  "before_each",
  "after_each",
  "setup",
  "teardown",
  "assert",
  "spy",
  "mock",
  "stub",
}

-- Exclude patterns
exclude_files = {
  ".luarocks",
  "lua_modules",
  ".install",
}

-- Warnings to ignore
ignore = {
  "211",  -- Unused local variable
  "212",  -- Unused argument
  "213",  -- Unused loop variable
  "431",  -- Shadowing upvalue
  "432",  -- Shadowing upvalue argument
}

-- Maximum line length
max_line_length = 120

-- Maximum code complexity
max_cyclomatic_complexity = 20

-- Check for unused variables
unused = true

-- Check for unused arguments
unused_args = true

-- Check for global variables
allow_defined_top = false

-- Files to check
files = {
  "handler.lua",
  "schema.lua",
  "modules/",
  "rules/",
  "detectors/",
  "storage/",
  "utils/",
}

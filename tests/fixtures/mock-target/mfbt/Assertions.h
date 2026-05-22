/* mfbt/Assertions.h — mock Mozilla assertions (infrastructure, no bugs) */
#pragma once

#define MOZ_ASSERT(cond) do { if (!(cond)) __builtin_trap(); } while(0)
#define MOZ_RELEASE_ASSERT(cond) MOZ_ASSERT(cond)
#define MOZ_CRASH(msg) __builtin_trap()
#define MOZ_ASSERT_UNREACHABLE(msg) __builtin_trap()

// SPDX-License-Identifier: GPL-2.0-only
///
/// Find usages of:
/// - msecs_to_jiffies(value*1000)
/// - msecs_to_jiffies(value*MSEC_PER_SEC)
///
// Confidence: High
// Copyright: (C) 2024 Easwar Hariharan, Microsoft
// Keywords: secs, seconds, jiffies
//

virtual patch
virtual report

@depends on patch@ constant C; @@

- msecs_to_jiffies(C * 1000)
+ secs_to_jiffies(C)

@depends on patch@ constant C; @@

- msecs_to_jiffies(C * MSEC_PER_SEC)
+ secs_to_jiffies(C)

// Dummy rule for report mode that would otherwise be empty and make spatch
// fail ("No rules apply.")
@script:python depends on report@
@@

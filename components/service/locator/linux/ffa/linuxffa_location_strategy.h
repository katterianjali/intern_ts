/*
 * Copyright (c) 2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef LINUXFFA_LOCATION_STRATEGY_H
#define LINUXFFA_LOCATION_STRATEGY_H

#include <service_locator.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Returns a service_location_strategy for locating a service instance
 * hosted in a secure partition, accessed using FFA from Linux userspace.
 * Relies on an FFA Linux kernel driver.
 */
const struct service_location_strategy *linuxffa_location_strategy(void);

#ifdef __cplusplus
}
#endif

#endif /* LINUXFFA_LOCATION_STRATEGY_H */
/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <cstring>
#include "crypto_test_vectors.h"

void crypto_test_vectors::plaintext_1_len_610(std::vector<uint8_t> &plaintext)
{
	/* Plaintext 1 - data length 610 bytes */
	const uint8_t data[] =
	{
		0x00,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x21,0x00,0x00,0x00,
		0x53,0x70,0x65,0x63,0x20,0x49,0x44,0x20,0x45,0x76,0x65,0x6e,0x74,0x30,0x33,0x00,
		0x00,0x00,0x00,0x00,0x00,0x02,0x02,0x01,0x01,0x00,0x00,0x00,0x0b,0x00,0x20,0x00,
		0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x0b,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x11,
		0x00,0x00,0x00,0x53,0x74,0x61,0x72,0x74,0x75,0x70,0x4c,0x6f,0x63,0x61,0x6c,0x69,
		0x74,0x79,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x00,
		0x0b,0x00,0xa8,0x4f,0xb4,0x7b,0x54,0xd9,0x4b,0xab,0x49,0x73,0x63,0xf7,0x9b,0xfc,
		0x66,0xcb,0x85,0x12,0xab,0x18,0x6f,0x24,0x74,0x01,0x5d,0xcf,0x33,0xf3,0x80,0x9e,
		0x9b,0x20,0x05,0x00,0x00,0x00,0x42,0x4c,0x5f,0x32,0x00,0x00,0x00,0x00,0x00,0x01,
		0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x0b,0x00,0x2f,0xd3,0x43,0x6c,0x6f,0xef,0x9b,
		0x11,0xc2,0x16,0xdd,0x1f,0x8b,0xdf,0x9b,0xa5,0x24,0x14,0xa5,0xc1,0x97,0x0c,0x3a,
		0x6c,0x78,0xbf,0xef,0x64,0x0f,0xc1,0x23,0xe1,0x06,0x00,0x00,0x00,0x42,0x4c,0x5f,
		0x33,0x31,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x0b,
		0x00,0xf3,0xde,0x4e,0x17,0xa1,0xa5,0xa7,0xfe,0xd9,0xd9,0xf4,0x16,0x3c,0x49,0x36,
		0x7e,0xae,0xf7,0x2f,0x2a,0xa8,0x87,0xe6,0xb6,0x22,0x89,0xcd,0x27,0xdc,0x1c,0x80,
		0x25,0x0a,0x00,0x00,0x00,0x48,0x57,0x5f,0x43,0x4f,0x4e,0x46,0x49,0x47,0x00,0x00,
		0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x0b,0x00,0x4e,0xe4,0x8e,
		0x5a,0xe6,0x50,0xed,0xe0,0xb5,0xa3,0x54,0x8a,0x1f,0xd6,0x0e,0x8a,0xea,0x0e,0x71,
		0x75,0x0e,0xa4,0x3f,0x82,0x76,0xce,0xaf,0xcd,0x7c,0xb0,0x91,0xe0,0x0e,0x00,0x00,
		0x00,0x53,0x4f,0x43,0x5f,0x46,0x57,0x5f,0x43,0x4f,0x4e,0x46,0x49,0x47,0x00,0x00,
		0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x0b,0x00,0x62,0x22,0x4f,
		0x0f,0xb0,0x5d,0xb4,0x77,0x1b,0x3f,0xa5,0x2e,0xab,0x76,0x1e,0x61,0x17,0xb8,0xc6,
		0x6e,0xac,0x8c,0xc8,0x4d,0x2e,0xb0,0x7d,0x70,0x08,0x60,0x4b,0x41,0x06,0x00,0x00,
		0x00,0x42,0x4c,0x5f,0x33,0x32,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,
		0x00,0x00,0x00,0x0b,0x00,0x39,0xd2,0xb8,0x5d,0x93,0x5d,0xf6,0xd8,0xf8,0xed,0x0c,
		0x1a,0x3a,0xe3,0xc8,0x90,0x72,0x19,0xf4,0x88,0x5c,0x79,0x15,0x05,0x7b,0xf0,0x76,
		0xdb,0xc1,0x4c,0x5d,0x77,0x12,0x00,0x00,0x00,0x42,0x4c,0x33,0x32,0x5f,0x45,0x58,
		0x54,0x52,0x41,0x31,0x5f,0x49,0x4d,0x41,0x47,0x45,0x00,0x00,0x00,0x00,0x00,0x01,
		0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x0b,0x00,0xb5,0xd6,0x08,0x61,0xdd,0xfa,0x6d,
		0xda,0xa3,0xf7,0xa5,0xde,0xd6,0x8f,0x6f,0x39,0x25,0xb1,0x57,0xfa,0x3e,0xdb,0x46,
		0x42,0x58,0x24,0x8e,0x81,0x1c,0x45,0x5d,0x38,0x06,0x00,0x00,0x00,0x42,0x4c,0x5f,
		0x33,0x33,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x0b,
		0x00,0x25,0x10,0x60,0x5d,0xd4,0xbc,0x9d,0x82,0x7a,0x16,0x9f,0x8a,0xcc,0x47,0x95,
		0xa6,0xfd,0xca,0xa0,0xc1,0x2b,0xc9,0x99,0x8f,0x51,0x20,0xff,0xc6,0xed,0x74,0x68,
		0x5a,0x0d,0x00,0x00,0x00,0x4e,0x54,0x5f,0x46,0x57,0x5f,0x43,0x4f,0x4e,0x46,0x49,
		0x47,0x00
	};

	plaintext.resize(sizeof(data));
	memcpy(&plaintext[0], data, sizeof(data));
}

void crypto_test_vectors::sha256_1(std::vector<uint8_t> &hash)
{
	/* SHA256 for plaintext_1 */
	const uint8_t data[] =
	{
		0x47, 0x25, 0x0e, 0xe2, 0x39, 0xe2, 0x87, 0xfc,
		0x07, 0x0d, 0xce, 0x67, 0xe8, 0x96, 0x6f, 0xc8,
		0x42, 0xae, 0xe7, 0xaa, 0x7f, 0xa3, 0xbc, 0x3c,
		0xc9, 0x8e, 0x7e, 0x7a, 0xca, 0x24, 0x2c, 0xfc
	};

	hash.resize(sizeof(data));
	memcpy(&hash[0], data, sizeof(data));
}

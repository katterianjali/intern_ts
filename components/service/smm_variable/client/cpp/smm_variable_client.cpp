/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <cstring>
#include <protocols/rpc/common/packed-c/status.h>
#include <rpc_caller.h>
#include "smm_variable_client.h"

smm_variable_client::smm_variable_client() :
	m_caller(NULL),
	m_err_rpc_status(TS_RPC_CALL_ACCEPTED)
{

}

smm_variable_client::smm_variable_client(
	struct rpc_caller *caller) :
	m_caller(caller),
	m_err_rpc_status(TS_RPC_CALL_ACCEPTED)
{

}

smm_variable_client::~smm_variable_client()
{

}

void smm_variable_client::set_caller(struct rpc_caller *caller)
{
	m_caller = caller;
}

int smm_variable_client::err_rpc_status() const
{
	return m_err_rpc_status;
}

efi_status_t smm_variable_client::set_variable(
	const EFI_GUID &guid,
	const std::wstring &name,
	const std::string &data,
	uint32_t attributes)
{
	efi_status_t efi_status = EFI_NO_RESPONSE;

	std::vector<int16_t> var_name = to_variable_name(name);
	size_t name_size = var_name.size() * sizeof(int16_t);
	size_t data_size = data.size();
	size_t req_len = SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE_SIZE(name_size, data_size);

	rpc_call_handle call_handle;
	uint8_t *req_buf;

	call_handle = rpc_caller_begin(m_caller, &req_buf, req_len);

	if (call_handle) {

		uint8_t *resp_buf;
        size_t resp_len;
		int opstatus;

		SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE *access_var =
			(SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE*)req_buf;

		access_var->Guid = guid;
		access_var->NameSize = name_size;
		access_var->DataSize = data_size;
		access_var->Attributes = attributes;

		memcpy(access_var->Name, var_name.data(), name_size);
		memcpy(&req_buf[SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE_DATA_OFFSET(access_var)],
			data.data(), data_size);

		m_err_rpc_status = rpc_caller_invoke(m_caller, call_handle,
			SMM_VARIABLE_FUNCTION_SET_VARIABLE, &opstatus, &resp_buf, &resp_len);

		if (m_err_rpc_status == TS_RPC_CALL_ACCEPTED) {

			efi_status = opstatus;
		}

		rpc_caller_end(m_caller, call_handle);
	}

	return efi_status;
}

efi_status_t smm_variable_client::get_variable(
	const EFI_GUID &guid,
	const std::wstring &name,
	std::string &data)
{
	efi_status_t efi_status = EFI_NO_RESPONSE;

	std::vector<int16_t> var_name = to_variable_name(name);
	size_t name_size = var_name.size() * sizeof(int16_t);
	size_t data_size = 0;
	size_t req_len = SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE_SIZE(name_size, data_size);

	rpc_call_handle call_handle;
	uint8_t *req_buf;

	call_handle = rpc_caller_begin(m_caller, &req_buf, req_len);

	if (call_handle) {

		uint8_t *resp_buf;
        size_t resp_len;
		int opstatus;

		SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE *access_var =
			(SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE*)req_buf;

		access_var->Guid = guid;
		access_var->NameSize = name_size;
		access_var->DataSize = data_size;

		memcpy(access_var->Name, var_name.data(), name_size);

		m_err_rpc_status = rpc_caller_invoke(m_caller, call_handle,
			SMM_VARIABLE_FUNCTION_GET_VARIABLE, &opstatus, &resp_buf, &resp_len);

		if (m_err_rpc_status == TS_RPC_CALL_ACCEPTED) {

			efi_status = opstatus;

			if (!efi_status) {

				access_var = (SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE*)resp_buf;
				data_size = access_var->DataSize;
				const char *data_start = (const char*)
					&resp_buf[SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE_DATA_OFFSET(access_var)];

				data.assign(data_start, data_size);
			}
		}

		rpc_caller_end(m_caller, call_handle);
	}

	return efi_status;
}

efi_status_t smm_variable_client::get_next_variable_name(
	EFI_GUID &guid,
	std::wstring &name)
{
	efi_status_t efi_status = EFI_NO_RESPONSE;

	std::vector<int16_t> var_name = to_variable_name(name);
	size_t name_size = var_name.size() * sizeof(int16_t);
	size_t req_len = SMM_VARIABLE_COMMUNICATE_GET_NEXT_VARIABLE_NAME_SIZE(name_size);

	rpc_call_handle call_handle;
	uint8_t *req_buf;

	call_handle = rpc_caller_begin(m_caller, &req_buf, req_len);

	if (call_handle) {

		uint8_t *resp_buf;
        size_t resp_len;
		int opstatus;

		SMM_VARIABLE_COMMUNICATE_GET_NEXT_VARIABLE_NAME *next_var =
			(SMM_VARIABLE_COMMUNICATE_GET_NEXT_VARIABLE_NAME*)req_buf;

		next_var->Guid = guid;
		next_var->NameSize = name_size;

		memcpy(next_var->Name, var_name.data(), name_size);

		m_err_rpc_status = rpc_caller_invoke(m_caller, call_handle,
			SMM_VARIABLE_FUNCTION_GET_NEXT_VARIABLE_NAME, &opstatus, &resp_buf, &resp_len);

		if (m_err_rpc_status == TS_RPC_CALL_ACCEPTED) {

			efi_status = opstatus;

			if (!efi_status) {

				next_var = (SMM_VARIABLE_COMMUNICATE_GET_NEXT_VARIABLE_NAME*)resp_buf;
				guid = next_var->Guid;
				name = from_variable_name(next_var->Name, next_var->NameSize);
			}
		}

		rpc_caller_end(m_caller, call_handle);
	}

	return efi_status;
}

efi_status_t smm_variable_client::exit_boot_service()
{
	efi_status_t efi_status = EFI_NO_RESPONSE;

	size_t req_len = 0;
	rpc_call_handle call_handle;
	uint8_t *req_buf;

	call_handle = rpc_caller_begin(m_caller, &req_buf, req_len);

	if (call_handle) {

		uint8_t *resp_buf;
        size_t resp_len;
		int opstatus;

		m_err_rpc_status = rpc_caller_invoke(m_caller, call_handle,
			SMM_VARIABLE_FUNCTION_EXIT_BOOT_SERVICE, &opstatus, &resp_buf, &resp_len);

		if (m_err_rpc_status == TS_RPC_CALL_ACCEPTED) {

			efi_status = opstatus;
		}

		rpc_caller_end(m_caller, call_handle);
	}

	return efi_status;
}

std::vector<int16_t> smm_variable_client::to_variable_name(
	const std::wstring &string)
{
	std::vector<int16_t> var_name;

	for (size_t i = 0; i < string.size(); i++) {

		var_name.push_back((int16_t)string[i]);
	}

	var_name.push_back(0);

	return var_name;
}

const std::wstring smm_variable_client::from_variable_name(
	const int16_t *var_name,
	size_t name_size)
{
	std::wstring name;
	size_t num_chars = name_size / sizeof(int16_t);

	for (size_t i = 0; i < num_chars; i++) {

		if (!var_name[i])	break;  /* Reached null terminator */
		name.push_back((wchar_t)var_name[i]);
	}

	return name;
}

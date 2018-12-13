#!/usr/bin/env python
#
# Copyright 2018 Carter Yagemann
#
# This file is part of Barnum.
#
# Barnum is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Barnum is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Barnum.  If not, see <https://www.gnu.org/licenses/>.

import sys
from os import path
import json
import logger
import logging
import reader
from optparse import OptionParser, OptionGroup
import numpy as np
import random
from multiprocessing import cpu_count, Pool
from datetime import datetime
import traceback
import tempfile
import gzip

MODULE_NAME = 'Syscall'

# Windows API calls
WIN_API_CALLS = {"__exception__": 1, "timeGetTime": 124, "GetFileInformationByHandle": 97, "setsockopt": 256, "RegOpenKeyExW": 283, "sendto": 249, "NtOpenSection": 204, "GetCursorPos": 43, "GetShortPathNameW": 115, "GetForegroundWindow": 184, "GetComputerNameW": 45, "EncryptMessage": 162, "FindWindowA": 180, "LoadResource": 168, "SetWindowsHookExW": 214, "RegQueryValueExW": 296, "CryptDecrypt": 150, "GetSystemTimeAsFileTime": 122, "InternetCloseHandle": 23, "RegDeleteValueW": 298, "CryptEncrypt": 151, "RegSetValueExA": 293, "NtQueryAttributesFile": 81, "CryptProtectData": 146, "InternetConnectW": 12, "SHGetFolderPathW": 56, "PRF": 0, "GlobalMemoryStatus": 239, "LoadStringW": 190, "EnumServicesStatusW": 346, "GetFileVersionInfoSizeExW": 62, "FindWindowExA": 182, "NtTerminateThread": 177, "FindWindowW": 181, "GetKeyboardState": 232, "NtOpenKey": 349, "getsockname": 246, "RtlCreateUserThread": 178, "Module32FirstW": 133, "GetDiskFreeSpaceExW": 52, "NtLoadDriver": 229, "CreateJobObjectW": 1, "GetInterfaceInfo": 35, "OpenServiceW": 340, "vbe6_CallByName": 320, "CScriptElement_put_src": 312, "InternetOpenW": 10, "CopyFileW": 91, "CertOpenStore": 302, "HttpOpenRequestW": 18, "socket": 245, "OpenServiceA": 339, "EnumServicesStatusA": 345, "DrawTextExW": 188, "DnsQuery_UTF8": 31, "FindFirstFileExA": 88, "WSARecvFrom": 262, "GetComputerNameA": 44, "NtOpenThread": 172, "RtlAddVectoredContinueHandler": 272, "NtEnumerateValueKey": 354, "RemoveDirectoryW": 86, "_CreateWindowExW": 192, "RegCreateKeyExW": 285, "CryptAcquireContextW": 145, "StartServiceCtrlDispatcherW": 347, "NtSaveKey": 364, "NtOpenKeyEx": 350, "StartServiceA": 341, "OleConvertOLESTREAMToIStorage": 334, "CreateServiceW": 338, "WSARecv": 261, "NtDeviceIoControlFile": 75, "NtOpenFile": 72, "ActiveXObjectFncObj_Construct": 315, "NtSetContextThread": 174, "GetSystemTime": 120, "HttpSendRequestW": 20, "GetFileSize": 95, "getaddrinfo": 33, "CreateRemoteThread": 136, "GetFileInformationByHandleEx": 98, "CryptExportKey": 157, "MessageBoxTimeoutA": 185, "RtlCreateUserProcess": 198, "GetFileType": 94, "NtDeleteKey": 358, "NtSuspendThread": 175, "WNetGetProviderNameW": 41, "NtUnmapViewOfSection": 205, "RtlDecompressFragment": 238, "CryptProtectMemory": 148, "NtDuplicateObject": 224, "LoadStringA": 189, "NtWriteFile": 74, "NtOpenDirectoryObject": 79, "NtReadVirtualMemory": 207, "FindResourceExA": 166, "NetUserGetLocalGroups": 142, "InternetOpenUrlW": 14, "RegCloseKey": 301, "NtCreateKey": 348, "NtReplaceKey": 352, "closesocket": 258, "InternetWriteFile": 22, "NtCreateProcessEx": 196, "CreateDirectoryW": 83, "DeleteUrlCacheEntryA": 28, "GetSystemMetrics": 42, "NtMapViewOfSection": 211, "IsDebuggerPresent": 222, "CertCreateCertificateContext": 306, "_DialogBoxIndirectParamA": 193, "InternetQueryOptionA": 15, "NtQueryDirectoryFile": 76, "CoInitializeSecurity": 331, "HttpQueryInfoA": 38, "LookupPrivilegeValueW": 223, "RegEnumKeyExA": 289, "HttpSendRequestA": 19, "GetSystemWindowsDirectoryW": 106, "GetUserNameExA": 48, "InternetSetStatusCallback": 27, "RegEnumKeyW": 288, "RtlDispatchException": 275, "UnhookWindowsHookEx": 216, "SearchPathW": 116, "RtlCompressBuffer": 236, "GetAdaptersInfo": 36, "CryptDecryptMessage": 154, "SetStdHandle": 69, "GetAsyncKeyState": 231, "CreateActCtxW": 67, "InternetSetOptionA": 16, "NtResumeThread": 176, "SetFilePointer": 99, "NtQueryMultipleValueKey": 357, "COleScript_Compile": 307, "shutdown": 259, "ConnectEx": 268, "connect": 247, "NtGetContextThread": 173, "RegQueryInfoKeyA": 299, "vbe6_Close": 326, "CreateToolhelp32Snapshot": 130, "ObtainUserAgentString": 39, "NtSetValueKey": 355, "NtAllocateVirtualMemory": 206, "GetNativeSystemInfo": 227, "NtQueryKey": 363, "LdrUnloadDll": 218, "GetDiskFreeSpaceW": 51, "NtCreateMutant": 4, "NotifyBootConfigStatus": 65, "InternetGetConnectedStateExW": 26, "GetVolumePathNamesForVolumeNameW": 113, "NtCreateProcess": 195, "GetBestInterfaceEx": 40, "CreateDirectoryExW": 84, "FindResourceW": 165, "RegEnumValueA": 291, "CopyFileExW": 92, "TaskDialog": 66, "CopyFileA": 90, "vbe6_Invoke": 321, "CertOpenSystemStoreA": 303, "system": 129, "LookupAccountSidW": 57, "CryptHashData": 152, "RegSetValueExW": 294, "TransmitFile": 269, "DeleteService": 344, "SetUnhandledExceptionFilter": 270, "NtCreateThread": 170, "ShellExecuteExW": 126, "NtDeleteValueKey": 359, "FindWindowExW": 183, "RtlRemoveVectoredContinueHandler": 274, "URLDownloadToFileW": 6, "Module32NextW": 134, "UuidCreate": 59, "CoCreateInstanceEx": 332, "NtOpenProcess": 199, "GetFileVersionInfoW": 63, "NtWriteVirtualMemory": 208, "SizeofResource": 169, "NtLoadKey": 360, "WSAAccept": 260, "OpenSCManagerA": 335, "SetEndOfFile": 111, "CryptUnprotectData": 147, "ReadProcessMemory": 127, "CryptAcquireContextA": 144, "RtlAddVectoredExceptionHandler": 271, "InternetOpenA": 9, "NetUserGetInfo": 141, "EnumWindows": 50, "NtReadFile": 73, "NtCreateFile": 70, "CryptGenKey": 158, "LdrGetProcedureAddress": 220, "_vbe6_StringConcat": 316, "SendNotifyMessageA": 234, "NtLoadKey2": 361, "FindResourceA": 164, "RegCreateKeyExA": 284, "RegQueryInfoKeyW": 300, "Thread32First": 138, "IWbemServices_ExecMethodAsync": 281, "GetVolumePathNameW": 114, "LdrGetDllHandle": 219, "AssignProcessToJobObject": 3, "NtCreateSection": 201, "RegOpenKeyExA": 282, "GetFileAttributesExW": 110, "GetFileSizeEx": 96, "gethostbyname": 244, "SetFileInformationByHandle": 101, "GetSystemDirectoryW": 104, "IWbemServices_ExecQuery": 278, "GetVolumeNameForVolumeMountPointW": 112, "CDocument_write": 308, "SetWindowsHookExA": 213, "RtlDecompressBuffer": 237, "WSASocketA": 265, "SetErrorMode": 228, "NtCreateThreadEx": 171, "SendNotifyMessageW": 235, "_DialogBoxIndirectParamW": 194, "DecryptMessage": 163, "ReadCabinetState": 58, "CertOpenSystemStoreW": 304, "NtQueryFullAttributesFile": 82, "SetFileAttributesW": 108, "NtProtectVirtualMemory": 209, "InternetCrackUrlW": 8, "OleInitialize": 328, "CreateServiceA": 337, "Process32NextW": 132, "vbe6_GetObject": 318, "SetFileTime": 117, "NtQueryValueKey": 356, "GetAdaptersAddresses": 37, "WSASocketW": 266, "GetFileVersionInfoExW": 64, "vbe6_Open": 324, "DeleteFileW": 93, "WSAStartup": 243, "NtCreateDirectoryObject": 80, "OutputDebugStringA": 215, "IWbemServices_ExecMethod": 280, "NtClose": 225, "_NtRaiseException": 277, "StartServiceW": 342, "CreateRemoteThreadEx": 137, "NtQuerySystemInformation": 241, "CryptCreateHash": 159, "NtQuerySystemTime": 123, "GetTickCount": 121, "Process32FirstW": 131, "InternetReadFile": 21, "NtFreeVirtualMemory": 210, "CryptHashMessage": 156, "CoUninitialize": 330, "OpenSCManagerW": 336, "NtShutdownSystem": 242, "NtDeleteFile": 71, "NtMakeTemporaryObject": 202, "RegEnumKeyExW": 290, "CWindow_AddTimeoutCode": 311, "vbe6_CreateObject": 317, "RegEnumValueW": 292, "NtQueueApcThread": 179, "LdrLoadDll": 217, "CryptUnprotectMemory": 149, "NtRenameKey": 351, "NtSaveKeyEx": 365, "WriteConsoleW": 54, "CIFrameElement_CreateElement": 310, "GetTempPathW": 107, "NtLoadKeyEx": 362, "FindFirstFileExW": 89, "vbe6_Shell": 322, "InternetOpenUrlA": 13, "NtTerminateProcess": 200, "Thread32Next": 139, "ControlService": 343, "NetGetJoinInformation": 140, "CoCreateInstance": 327, "recv": 250, "send": 248, "FindResourceExW": 167, "SetInformationJobObject": 2, "CertControlStore": 305, "SetFilePointerEx": 100, "DeviceIoControl": 102, "NtOpenMutant": 5, "GetSystemWindowsDirectoryA": 105, "NtMakePermanentObject": 203, "CreateThread": 135, "CoInitializeEx": 329, "SHGetSpecialFolderLocation": 55, "WSAConnect": 267, "HttpOpenRequestA": 17, "InternetCrackUrlA": 7, "CImgElement_put_src": 314, "_CreateWindowExA": 191, "NtDelayExecution": 118, "GetUserNameW": 47, "MessageBoxTimeoutW": 186, "CryptDecodeMessage": 153, "vbe6_GetIDFromName": 319, "select": 255, "vbe6_Print": 325, "WriteProcessMemory": 128, "NetShareEnum": 212, "vbe6_Import": 323, "WSASendTo": 264, "GetSystemDirectoryA": 103, "GetUserNameExW": 49, "NtEnumerateKey": 353, "CryptDecodeObjectEx": 160, "CryptEncryptMessage": 155, "GetAddrInfoW": 34, "RegDeleteKeyW": 287, "DnsQuery_A": 30, "WriteConsoleA": 53, "CreateProcessInternalW": 125, "ioctlsocket": 257, "RtlRemoveVectoredExceptionHandler": 273, "RegisterHotKey": 68, "_RtlRaiseException": 276, "accept": 252, "InternetGetConnectedState": 24, "Ssl3GenerateKeyMaterial": 161, "GetTimeZoneInformation": 60, "DnsQuery_W": 32, "InternetGetConnectedStateExA": 25, "ExitWindowsEx": 221, "GetSystemInfo": 226, "RegDeleteKeyA": 286, "bind": 253, "DeleteUrlCacheEntryW": 29, "RegDeleteValueA": 297, "CElement_put_innerHTML": 313, "RegQueryValueExA": 295, "recvfrom": 251, "InternetConnectA": 11, "GetLocalTime": 119, "GetFileAttributesW": 109, "IWbemServices_ExecQueryAsync": 279, "NtUnloadDriver": 230, "CHyperlink_SetUrlComponent": 309, "GlobalMemoryStatusEx": 240, "listen": 254, "GetUserNameA": 46, "NtQueryInformationFile": 77, "NtCreateUserProcess": 197, "NtSetInformationFile": 78, "GetKeyState": 233, "WSASend": 263, "GetFileVersionInfoSizeW": 61, "DrawTextExA": 187, "RemoveDirectoryA": 85, "MoveFileWithProgressW": 87, "CoGetClassObject": 333}

# Exit codes
EXIT_INVALID_ARGS   = 1
EXIT_UNIMPLEMENTED  = 2
EXIT_RUNTIME_ERROR  = 3
EXIT_USER_INTERRUPT = 4

def clean_exit(error_code, message):
    """ Performs a clean exit, useful for when errors happen that can't be recovered from."""
    logger.log_critical(MODULE_NAME, message)
    logger.log_stop()
    sys.exit(error_code)

def save_sets():
    try:
        with open(options.output_sets, 'w') as ofile:
            for key in sets_meta:
                ofile.write('[' + str(key) + "]\n") # Header
                for item in sets_meta[key]:
                    ofile.write(item['base_dir'] + "\n")
    except:
        logger.log_error(MODULE_NAME, "Failed to save sets to " + str(options.output_sets))

def load_sets():
    if not path.isfile(options.input_sets):
        clean_exit(EXIT_INVALID_ARGS, "Cannot find file " + str(options.input_sets))

    set_key = None

    try:
        with open(options.input_sets, 'r') as ifile:
            for line in ifile:
                line = line.rstrip()
                if len(line) < 1:
                    continue
                if line[0] == '[':
                    set_key = line[1:-1]
                else:
                    # Line should be the path to a trace directory
                    if not root_dir in line:
                        logger.log_warning(MODULE_NAME, 'Input data specified with -i must be in ' + str(root_dir) + ', skipping')
                        continue
                    if not path.isdir(line):
                        logger.log_warning(MODULE_NAME, 'Cannot find directory ' + str(line) + ' to load data from, skipping')
                        continue
                    matches = [record for record in fs if record['base_dir'] == line]
                    if len(matches) < 1:
                        logger.log_warning(MODULE_NAME, 'Could not find data in directory ' + str(line) + ', skipping')
                        continue
                    sets_meta[set_key].append(matches[0])
    except:
        clean_exit(EXIT_RUNTIME_ERROR, "Failed to load sets from " + str(options.input_sets))

def build_model():
    """ Builds the LSTM model assuming two categories."""
    model = Sequential()

    model.add(Embedding(input_dim=options.embedding_in_dim,
                        output_dim=options.embedding_out_dim,
                        input_length=options.seq_len))

    model.add(LSTM(options.units))

    model.add(Dense(128))
    model.add(Activation('relu'))

    model.add(Dropout(options.dropout))

    model.add(Dense(options.max_classes))
    model.add(Activation('softmax'))

    opt = optimizers.RMSprop(lr=options.learning_rate, decay=options.learning_decay)
    model.compile(loss='sparse_categorical_crossentropy',
                  optimizer=opt,
                  metrics=['sparse_categorical_accuracy', 'sparse_top_k_categorical_accuracy'])

    logger.log_info(MODULE_NAME, 'Model Summary:')
    model.summary(print_fn=(lambda x: logger.log_info(MODULE_NAME, x)))

    return model

def parse_report(filepath):
    res = None

    if not path.isfile(filepath):
        logger.log_error(MODULE_NAME, str(filepath) + ' is not a file')
        return res

    try:
        with gzip.open(filepath, 'rt') as ifile:
            report = json.loads(ifile.read())
    except IOError:
        logger.log_error(MODULE_NAME, 'Failed to read ' + str(filepath))
        return res

    if not 'behavior' in report.keys() or 'processes' not in report['behavior'].keys():
        logger.log_error(MODULE_NAME, 'Report ' + str(filepath) + ' is missing required keys')
        return res

    calls = None
    for process in report['behavior']['processes']:
        if 'AcroRd32.exe' in process['process_path'] and 'calls' in process.keys():
            calls = process['calls']
            break
    if calls is None:
        logger.log_error(MODULE_NAME, 'Could not find AcroRd32.exe in ' + str(filepath))
        return res

    try:
        call_nums = [WIN_API_CALLS[call['api']] for call in calls]
    except KeyError:
        missing = list(set([call['api'] for call in calls if not call['api'] in WIN_API_CALLS.keys()]))
        logger.log_error(MODULE_NAME, 'WIN_API_CALLS missing: ' + json.dumps(missing))
        return res

    # Padding
    while len(call_nums) % options.seq_len != 0:
        call_nums.append(0)                 # Pad for sequence length
    while len(call_nums) / options.seq_len % options.batch_size != 0:
        call_nums += [0] * options.seq_len  # Pad for batch size
    call_nums += [0] * options.seq_len      # Pad for label offset
    # Reshape into sequences
    xs = np.reshape(call_nums, (-1, options.seq_len))[:-1]
    ys = np.reshape(call_nums, (-1, options.seq_len))[1:,0]
    # Reshape into batches
    xs_batched = np.reshape(xs, (-1, options.batch_size, options.seq_len))
    ys_batched = np.reshape(ys, (-1, options.batch_size))

    return zip(xs_batched, ys_batched)

def map_to_model(samples, f):
    """ A helper function because train_on_batch() and test_on_batch() are so similar."""
    random.shuffle(samples)
    # There's no point spinning up more worker threads than there are samples
    threads = min(options.threads, len(samples))

    pool = Pool(threads)
    traces = pool.map(parse_report, [sample['cuckoo_report'] for sample in samples])
    pool.close()
    batch_cnt = 0
    for trace in traces:
        if trace is None:
            continue
        for x_batch, y_batch in trace:
            yield f(x_batch, y_batch)
            batch_cnt += 1

    logger.log_info(MODULE_NAME, "Processed " + str(batch_cnt) + " batches, " + str(batch_cnt * options.batch_size) + " samples")

def train_model(training_set):
    """ Trains the LSTM model."""
    start_time = datetime.now()
    # Checkpointing for saving model weights
    freq_c = options.checkpoint_interval * 60
    last_c = datetime.now()
    # For reporting current metrics
    freq_s = options.status_interval * 60
    last_s = datetime.now()

    res = [0.0] * len(model.metrics_names)
    batches = 0
    for status in map_to_model(training_set, model.train_on_batch):
        if status is None:
            break
        for stat in range(len(status)):
            res[stat] += status[stat]
        batches += 1
        # Print current metrics every minute
        if (datetime.now() - last_s).total_seconds() > freq_s:
            c_metrics = [status / batches for status in res]
            c_metrics_str = ', '.join([str(model.metrics_names[x]) + ' ' + str(c_metrics[x]) for x in range(len(c_metrics))])
            logger.log_info(MODULE_NAME, 'Status: ' + c_metrics_str)
            last_s = datetime.now()
        # Save current weights at user specified frequency
        if freq_c > 0 and (datetime.now() - last_c).total_seconds() > freq_c:
            logger.log_debug(MODULE_NAME, 'Checkpointing weights')
            try:
                model.save_weights(options.save_weights)
            except:
                generator.stop_generator(10)
                clean_exit(EXIT_RUNTIME_ERROR, "Failed to save LSTM weights:\n" + str(traceback.format_exc()))
            last_c = datetime.now()

    if batches < 1:
        logger.log_warning(MODULE_NAME, 'Testing set did not generate a full batch of data, cannot test')
        return

    for stat in range(len(res)):
        res[stat] /= batches

    logger.log_info(MODULE_NAME, 'Results: ' + ', '.join([str(model.metrics_names[x]) + ' ' + str(res[x]) for x in range(len(res))]))
    logger.log_debug(MODULE_NAME, 'Training finished in ' + str(datetime.now() - start_time))

    return res[0] # Average Loss

def test_model(testing_set):
    """ Test the LSTM model."""
    # For reporting current metrics
    freq_s = options.status_interval * 60
    last_s = datetime.now()

    res = [0.0] * len(model.metrics_names)
    batches = 0

    for status in map_to_model(testing_set, model.test_on_batch):
        if status is None:
            break
        for stat in range(len(status)):
            res[stat] += status[stat]
        batches += 1
        # Print current metrics every minute
        if (datetime.now() - last_s).total_seconds() > freq_s:
            c_metrics = [status / batches for status in res]
            c_metrics_str = ', '.join([str(model.metrics_names[x]) + ' ' + str(c_metrics[x]) for x in range(len(c_metrics))])
            logger.log_info(MODULE_NAME, 'Status: ' + c_metrics_str)
            last_s = datetime.now()

    if batches < 1:
        logger.log_warning(MODULE_NAME, 'Testing set did not generate a full batch of data, cannot test')
        return

    for stat in range(len(res)):
        res[stat] /= batches

    logger.log_info(MODULE_NAME, 'Results: ' + ', '.join([str(model.metrics_names[x]) + ' ' + str(res[x]) for x in range(len(res))]))

def eval_model(samples):
    """ Evaluate the LSTM model."""
    temp_dir = tempfile.mkdtemp(suffix='-lstm-syscall')
    logger.log_info(MODULE_NAME, 'Evaluation results will be written to ' + temp_dir)
    random.shuffle(samples)

    for sample in samples:
        trace = parse_report(sample['cuckoo_report'])
        if trace is None:
            continue

        o_filename = sample['label'] + '-' + path.basename(sample['base_dir']) + '.gz'
        o_filepath = path.join(temp_dir, o_filename)
        logger.log_debug(MODULE_NAME, 'Writing to ' + o_filepath)

        with gzip.open(o_filepath, 'wt') as ofile:
            for x_batch, y_batch in trace:
                ps = model.predict_on_batch(np.array(x_batch)).tolist()
                cs = [max(p) for p in ps]                        # Max confidence
                ms = [p.index(max(p)) for p in ps]               # Most likely label
                ts = [int(a == b) for a, b in zip(ms, y_batch)]  # Compare prediction to real label
                for c, m, t, y in zip(cs, ms, ts, y_batch):
                    ofile.write(str(t) + ',' + str(m) + ',' + str(c) + ',' + str(y) + "\n")

if __name__ == '__main__':

    # Parse input arguments
    parser = OptionParser(usage='Usage: %prog [options] pt_directory')

    parser_group_sys = OptionGroup(parser, 'System Options')
    parser_group_sys.add_option('-l', '--logging', action='store', dest='log_level', type='int', default=20,
                                help='Logging level (10: Debug, 20: Info, 30: Warning, 40: Error, 50: Critical) (default: Info)')
    parser_group_sys.add_option('--status-interval', action='store', dest='status_interval', type='int', default=60,
                                help='How frequently (in minutes) to print the current status of training or testing (default: 60)')
    parser_group_sys.add_option('-t', '--threads', action='store', dest='threads', type='int', default=cpu_count(),
                                help='Number of threads to use when parsing PT traces (default: number of CPU cores)')
    parser_group_sys.add_option('--skip-test', action='store_true', dest='skip_test',
                                help='Skip the generalization testing stage, useful when combined with saving to just make and store a model')
    parser_group_sys.add_option('--skip-eval', action='store_true', dest='skip_eval',
                                help='Skip the evaluation stage, useful when combined with saving to just make and store a model')
    parser.add_option_group(parser_group_sys)

    parser_group_data = OptionGroup(parser, 'Data Options')
    parser_group_data.add_option('--train-size', action='store', dest='train_size', type='int', default=8,
                                 help='Number of traces to train on (default: 8)')
    parser_group_data.add_option('--test-size-benign', action='store', dest='test_size_b', type='int', default=2,
                                 help='Number of benign traces to test on (default: 2)')
    parser_group_data.add_option('--test-size-malicious', action='store', dest='test_size_m', type='int', default=2,
                                 help='Number of malicious traces to test on (default: 2)')
    parser_group_data.add_option('-o', '--output-sets', action='store', dest='output_sets', type='string', default='',
                                 help='Write the picked samples to the provided file so these sets can be resused in future runs (see -i)')
    parser_group_data.add_option('-i', '--input-sets', action='store', dest='input_sets', type='string', default='',
                                 help='Instead of using train-size, test-size, and ratio, load the samples from this file (see -o).')
    parser.add_option_group(parser_group_data)

    parser_group_lstm = OptionGroup(parser, 'LSTM Options')
    parser_group_lstm.add_option('-s', '--sequence-len', action='store', dest='seq_len', type='int', default=32,
                                 help='Length of sequences fed into LSTM (default: 32)')
    parser_group_lstm.add_option('-b', '--batch-size', action='store', dest='batch_size', type='int', default=128,
                                 help='Number of sequences per batch (default: 128)')
    parser_group_lstm.add_option('-e', '--epochs', action='store', dest='epochs', type='int', default=16,
                                 help='Number of times to iterate over test sets (default: 16)')
    parser_group_lstm.add_option('--units', action='store', dest='units', type='int', default=128,
                                 help='Number of units to use in LSTM (default: 128)')
    parser_group_lstm.add_option('--max-classes', action='store', dest='max_classes', type='int', default=400,
                                 help='The max number of classes to use (default: 400)')
    parser_group_lstm.add_option('--embedding-input-dimension', action='store', dest='embedding_in_dim', type='int', default=400,
                                 help='The input dimension of the embedding layer (default: 400)')
    parser_group_lstm.add_option('--embedding-output-dimension', action='store', dest='embedding_out_dim', type='int', default=400,
                                 help='The output dimension of the embedding layer (default: 400)')
    parser_group_lstm.add_option('--dropout', action='store', dest='dropout', type='float', default=0.5,
                                 help='The dropout rate in the dense layer (default: 0.5)')
    parser_group_lstm.add_option('--learning-rate', action='store', dest='learning_rate', type='float', default=0.001,
                                 help='Learning rate for the RMSprop optimizer (default: 0.001)')
    parser_group_lstm.add_option('--learning-decay', action='store', dest='learning_decay', type='float', default=0.0,
                                 help='Decay rate of optimizer (default: 0.0)')
    parser_group_lstm.add_option('--save-model', action='store', dest='save_model', type='string', default='',
                                 help='Save the generated model to the provided filepath in JSON format')
    parser_group_lstm.add_option('--save-weights', action='store', dest='save_weights', type='string', default='',
                                 help='Save the weights after training to the provided filepath in H5 format')
    parser_group_lstm.add_option('--checkpoint', action='store', dest='checkpoint_interval', type='int', default=0,
                                 help='Save current weights every X minutes (default: only save after training)')
    parser_group_lstm.add_option('--use-model', action='store', dest='use_model', type='string', default='',
                                 help='Load the model from the provided filepath instead of building a new one')
    parser_group_lstm.add_option('--use-weights', action='store', dest='use_weights', type='string', default='',
                                 help='Load weights from the provided filepath (this will skip training and head straight to evaluation)')
    parser.add_option_group(parser_group_lstm)

    options, args = parser.parse_args()

    if len(args) < 1:
        parser.print_help()
        sys.exit(0)

    # Keras likes to print $@!& to stdout, so don't import it until after the input parameters have been validated
    from keras.models import Model, Sequential, model_from_json
    from keras.layers import Dense, LSTM, Embedding, Activation, Dropout
    from keras import optimizers

    root_dir = args[0]

    # Initialization
    logger.log_start(options.log_level)

    # Input validation
    errors = False
    if options.threads < 1:
        logger.log_error(MODULE_NAME, 'Parsing requires at least 1 thread')
        errors = True

    if options.seq_len < 2:
        logger.log_error(MODULE_NAME, 'Sequence length must be at least 2')
        errors = True

    if options.batch_size < 1:
        logger.log_error(MODULE_NAME, 'Batch size must be at least 1')
        errors = True

    if options.epochs < 1:
        logger.log_error(MODULE_NAME, 'Epochs must be at least 1')
        errors = True

    if options.train_size < 1:
        logger.log_error(MODULE_NAME, 'Training size must be at least 1')
        errors = True

    if options.test_size_b < 1:
        logger.log_error(MODULE_NAME, 'Benign test size must be at least 1')
        errors = True

    if options.test_size_m < 1:
        logger.log_error(MODULE_NAME, 'Malicious test size must be at least 1')
        errors = True

    if options.units < 1:
        logger.log_error(MODULE_NAME, 'LSTM must have at least 1 unit')
        errors = True

    if options.embedding_in_dim < 1:
        logger.log_error(MODULE_NAME, 'Embedding input dimension must be at least 1')
        errors = True

    if options.embedding_out_dim < 1:
        logger.log_error(MODULE_NAME, 'Embedding output dimension must be at least 1')
        errors = True

    if options.dropout < 0 or options.dropout >= 1:
        logger.log_error(MODULE_NAME, 'Dropout rate must be in range [0, 1)')
        errors = True

    if options.checkpoint_interval < 0:
        logger.log_error(MODULE_NAME, 'Checkpoint interval cannot be negative')
        errors = True

    if options.checkpoint_interval > 0 and len(options.save_weights) < 1:
        logger.log_error(MODULE_NAME, 'Checkpointing requires --save-weights')
        errors = True

    if errors:
        clean_exit(EXIT_INVALID_ARGS, 'Failed to parse options')

    logger.log_info(MODULE_NAME, 'Scanning ' + str(root_dir))
    fs = reader.parse_pt_dir(root_dir)
    if fs is None or len(fs) == 0:
        clean_exit(EXIT_INVALID_ARGS, 'Directory ' + str(root_dir) + ' does not contain the expected file layout')

    fs = [x for x in fs if 'cuckoo_report' in x.keys()]

    benign = [x for x in fs if x['label'] == 'benign']
    malicious = [x for x in fs if x['label'] == 'malicious']

    logger.log_info(MODULE_NAME, 'Found ' + str(len(benign)) + ' benign traces and ' + str(len(malicious)) + ' malicious traces')

    sets_meta = {'b_train': [], 'm_test': [], 'b_test': []}

    # User has the option of providing an input file that tells us which samples to use.
    if len(options.input_sets) > 0:
        load_sets()
    # Otherwise, we're going to pick randomly based on train-size, test-size, and ratio.
    else:
        b_train_size = int(options.train_size)
        b_test_size = int(options.test_size_b)
        m_test_size = int(options.test_size_m)

        if len(benign) < b_train_size + b_test_size:
            clean_exit(EXIT_RUNTIME_ERROR, 'Not enough benign samples! Need ' + str(b_train_size + b_test_size) + ' have ' + str(len(benign)))

        if len(malicious) < m_test_size:
            clean_exit(EXIT_RUNTIME_ERROR, 'Not enough malicious samples! Need ' + str(m_test_size) + ' have ' + str(len(malicious)))

        random.seed() # We don't need a secure random shuffle, so this is good enough
        random.shuffle(benign)
        random.shuffle(malicious)

        if b_train_size > 0:
            sets_meta['b_train'] = benign[:b_train_size]
        if b_test_size > 0:
            sets_meta['b_test'] = benign[-b_test_size:]
        if m_test_size > 0:
            sets_meta['m_test'] = malicious[-m_test_size:]

    logger.log_info(MODULE_NAME, 'Selected ' + ', '.join([str(len(sets_meta[x])) + ' ' +  str(x) for x in sets_meta.keys()]))

    if len(options.output_sets) > 0:
        save_sets()

    # Build model if user didn't provide one
    if len(options.use_model) == 0:
        logger.log_info(MODULE_NAME, 'Building LSTM model')
        try:
            model = build_model()
        except:
            clean_exit(EXIT_RUNTIME_ERROR, "Error while building model:\n" + str(traceback.format_exc()))
    else:
        logger.log_info(MODULE_NAME, 'Restoring LSTM model from provided filepath')
        try:
            with open(options.use_model, 'r') as ifile:
                model = model_from_json(ifile.read())
            model.compile(loss='sparse_categorical_crossentropy',
                          optimizer='rmsprop',
                          metrics=['sparse_categorical_accuracy'])
        except:
            clean_exit(EXIT_RUNTIME_ERROR, 'Failed to load model from JSON file')

    if len(options.save_model) > 0:
        try:
            logger.log_info(MODULE_NAME, 'Saving LSTM model')
            with open(options.save_model, 'w') as ofile:
                ofile.write(model.to_json())
        except:
            clean_exit(EXIT_RUNTIME_ERROR, "Failed to save LSTM model:\n" + str(traceback.format_exc()))

    # Train model if user didn't already provide weights
    if len(options.use_weights) == 0:
        prev_loss = 10000
        for epoch in range(options.epochs):
            logger.log_info(MODULE_NAME, 'Starting training epoch ' + str(epoch + 1))
            try:
                curr_loss = train_model(sets_meta['b_train'])
            except KeyboardInterrupt:
                clean_exit(EXIT_USER_INTERRUPT, 'Keyboard interrupt, cleaning up...')
            except:
                clean_exit(EXIT_RUNTIME_ERROR, "Unexpected error:\n" + str(traceback.format_exc()))
            if curr_loss > prev_loss:
                logger.log_info(MODULE_NAME, "Loss metric didn't improve, stopping early")
                break
            else:
                prev_loss = curr_loss
    else:
        logger.log_info(MODULE_NAME, 'Restoring LSTM weights from provided filepath')
        try:
            model.load_weights(options.use_weights)
        except:
            clean_exit(EXIT_RUNTIME_ERROR, 'Failed to load weights from file')

    if len(options.save_weights) > 0:
        try:
            model.save_weights(options.save_weights)
        except:
            clean_exit(EXIT_RUNTIME_ERROR, "Failed to save LSTM weights:\n" + str(traceback.format_exc()))

    # Test model
    if not options.skip_test:
        logger.log_info(MODULE_NAME, 'Starting testing')
        try:
            test_model(sets_meta['b_test'])
        except KeyboardInterrupt:
            clean_exit(EXIT_USER_INTERRUPT, 'Keyboard interrupt, cleaning up...')
        except:
            clean_exit(EXIT_RUNTIME_ERROR, "Unexpected error:\n" + str(traceback.format_exc()))
    else:
        logger.log_info(MODULE_NAME, 'Skipping testing')

    # Evaluating model
    if not options.skip_eval:
        logger.log_info(MODULE_NAME, 'Starting evaluation')
        try:
            eval_model(sets_meta['b_test'] + sets_meta['m_test'])
        except KeyboardInterrupt:
            clean_exit(EXIT_USER_INTERRUPT, 'Keyboard interrupt, cleaning up...')
        except:
            clean_exit(EXIT_RUNTIME_ERROR, "Unexpected error:\n" + str(traceback.format_exc()))
    else:
        logger.log_info(MODULE_NAME, 'Skipping evaluation')

    # Cleanup
    logger.log_info(MODULE_NAME, 'Cleaning up and exiting')
    logger.log_stop()

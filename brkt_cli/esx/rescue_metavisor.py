# Copyright 2016 Bracket Computing, Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
# https://github.com/brkt/brkt-cli/blob/master/LICENSE
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and
# limitations under the License.
import logging

log = logging.getLogger(__name__)

def rescue_metavisor_vcenter(vc_swc, user_data_str, vm_name):
    vm = vc_swc.find_vm(vm_name)
    if vm is None:
        log.error("Failed to find VM %s", vm_name);
        raise Exception("VM not found")
    vc_swc.send_userdata(vm, user_data_str)

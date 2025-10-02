#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
阿里云 AK/SK 鉴定与只读审计报告工具（含 OSS 权限与全量对象枚举）
依赖：
    pip install aliyun-python-sdk-core-v3 oss2
安全提示：仅在授权环境中使用。
"""

import os
import sys
import csv
import json
import time
import traceback
from datetime import datetime
from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.request import CommonRequest
from aliyunsdkcore.acs_exception.exceptions import ClientException, ServerException

# OSS SDK
import oss2

# ========= 可调整默认区域（可多选） =========
DEFAULT_REGIONS = ["cn-hangzhou", "cn-shanghai", "cn-beijing", "ap-southeast-1"]

# ========= OSS 枚举参数（可按需调整） =========
OSS_PROGRESS_INTERVAL = 1000     # 每列举多少个对象打印一次进度
OSS_MAX_BUCKETS_TO_LIST = None   # 仅调试时限制桶数量（None 表示不限制）

class AliyunAuditor:
    def __init__(self, access_key_id, access_key_secret, regions=None):
        self.ak = access_key_id
        self.sk = access_key_secret
        self.regions = regions or DEFAULT_REGIONS
        # 任意区域都可创建 client
        self.client = AcsClient(self.ak, self.sk, self.regions[0])
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.report_dir = f"aliyun_ak_audit_{ts}"
        os.makedirs(self.report_dir, exist_ok=True)

        # 数据容器
        self.data = {
            "identity": {},
            "tests": {},
            "resources": {
                "ram": {},
                "ecs": {"instances": [], "security_groups": [], "key_pairs": []},
                "rds": {"instances": []},
                "vpc": {"vpcs": [], "vswitches": [], "route_tables": [], "nat_gateways": []},
                "kms": {"keys": []},
                "actiontrail": {"trails": []},
                "oss": {"buckets": [], "grand_total_objects": 0}
            },
            "risks": {"critical": [], "high": [], "medium": [], "low": [], "info": []},
            "stats": {},
            "assessment": {},
        }

        print(f"📁 报告目录：{self.report_dir}/")

    # ---------------- 基础工具 ----------------
    def call_api(self, domain, version, action, method="POST", params=None, region_id=None, timeout=10):
        req = CommonRequest()
        req.set_method(method)
        req.set_protocol_type('https')
        req.set_domain(domain)
        req.set_version(version)
        req.set_action_name(action)
        if params:
            for k, v in params.items():
                if v is not None:
                    req.add_query_param(k, v)
        if region_id:
            req.add_query_param("RegionId", region_id)
        return self.client.do_action_with_exception(req)

    # ---------------- 身份与可选链路 ----------------
    def test_identity(self):
        print("="*80)
        print("🔐 身份鉴定 (STS:GetCallerIdentity)")
        print("="*80)
        raw = self.call_api("sts.aliyuncs.com", "2015-04-01", "GetCallerIdentity", "POST")
        obj = json.loads(raw)
        self.data["identity"] = {
            "AccountId": obj.get("AccountId"),
            "Arn": obj.get("Arn"),
            "UserId": obj.get("UserId"),
            "CheckedAt": datetime.now().isoformat(),
        }
        self.data["tests"]["sts_get_caller_identity"] = {"status": "SUCCESS", "response": obj}
        print("✅ 通过")
        print(f"   AccountId : {obj.get('AccountId')}")
        print(f"   Arn       : {obj.get('Arn')}")
        print(f"   UserId    : {obj.get('UserId')}")
        if obj.get("Arn", "").endswith(":root"):
            self.data["risks"]["critical"].append({
                "type": "ROOT_CREDENTIAL_IN_USE",
                "resource": obj.get("Arn"),
                "description": "当前使用的是主账号(root)的 AccessKey",
                "recommendation": "强烈建议：停用 root AK，使用 RAM 用户 + 最小权限 + MFA"
            })

    def optional_nls_token_test(self):
        print("\n🗣 语音链路可选验证 (NLS:CreateToken)")
        try:
            raw = self.call_api("nls-meta.cn-shanghai.aliyuncs.com", "2019-02-28",
                                "CreateToken", "POST", region_id="cn-shanghai")
            obj = json.loads(raw)
            token = obj["Token"]["Id"]
            expire = obj["Token"]["ExpireTime"]
            self.data["tests"]["nls_create_token"] = {"status": "SUCCESS", "token": token, "expire": expire}
            print("✅ 通过：", token)
        except Exception as e:
            self.data["tests"]["nls_create_token"] = {"status": "FAILED", "error": str(e)}
            print("⚠️ 跳过：", e)

    # ---------------- RAM ----------------
    def enumerate_ram(self):
        print("\n👤 RAM 枚举（用户/角色/策略 摘要）")
        ram = {"users": [], "roles": [], "attached_policies": {}}
        try:
            raw = self.call_api("ram.aliyuncs.com", "2015-05-01", "ListUsers", "POST")
            obj = json.loads(raw)
            for u in obj.get("Users", {}).get("User", []):
                ram["users"].append({
                    "UserName": u.get("UserName"),
                    "UserId": u.get("UserId"),
                    "DisplayName": u.get("DisplayName"),
                    "CreateDate": u.get("CreateDate"),
                })
        except Exception as e:
            print("   ❌ ListUsers：", e)

        try:
            raw = self.call_api("ram.aliyuncs.com", "2015-05-01", "ListRoles", "POST")
            obj = json.loads(raw)
            for r in obj.get("Roles", {}).get("Role", []):
                ram["roles"].append({
                    "RoleName": r.get("RoleName"),
                    "Arn": r.get("Arn"),
                    "CreateDate": r.get("CreateDate"),
                })
        except Exception as e:
            print("   ❌ ListRoles：", e)

        for u in ram["users"][:50]:
            name = u["UserName"]
            try:
                raw = self.call_api("ram.aliyuncs.com", "2015-05-01", "ListPoliciesForUser",
                                    "POST", params={"UserName": name})
                obj = json.loads(raw)
                pols = [{"PolicyName": p.get("PolicyName"), "PolicyType": p.get("PolicyType")}
                        for p in obj.get("Policies", {}).get("Policy", [])]
                ram["attached_policies"][name] = pols
            except Exception:
                ram["attached_policies"][name] = []

        self.data["resources"]["ram"] = ram
        print(f"   用户: {len(ram['users'])}，角色: {len(ram['roles'])}")

        for u in ram["users"]:
            pols = self.data["resources"]["ram"]["attached_policies"].get(u["UserName"], [])
            if len(pols) > 10:
                self.data["risks"]["medium"].append({
                    "type": "RAM_EXCESSIVE_POLICIES",
                    "resource": u["UserName"],
                    "description": f"RAM 用户附加策略数量较多：{len(pols)}",
                    "recommendation": "审查并收敛权限，最小化授权"
                })

    # ---------------- ECS / SG / KeyPairs ----------------
    def enumerate_ecs(self):
        print("\n💻 ECS / 安全组 / 密钥对（多地域）")
        for region in self.regions:
            print(f"   区域：{region}")
            try:
                raw = self.call_api("ecs.aliyuncs.com", "2014-05-26", "DescribeInstances",
                                    "POST", params={"PageSize": 100}, region_id=region)
                obj = json.loads(raw)
                for ins in obj.get("Instances", {}).get("Instance", []):
                    self.data["resources"]["ecs"]["instances"].append({
                        "InstanceId": ins.get("InstanceId"),
                        "InstanceName": ins.get("InstanceName"),
                        "RegionId": region,
                        "ZoneId": ins.get("ZoneId"),
                        "Status": ins.get("Status"),
                        "VpcId": ins.get("VpcAttributes", {}).get("VpcId"),
                        "VSwitchId": ins.get("VpcAttributes", {}).get("VSwitchId"),
                        "PrivateIp": ",".join(ins.get("InnerIpAddress", {}).get("IpAddress", [])),
                        "PublicIp": ",".join(ins.get("PublicIpAddress", {}).get("IpAddress", [])),
                        "EipAddress": (ins.get("EipAddress") or {}).get("IpAddress", "")
                    })
            except Exception as e:
                print("      ❌ DescribeInstances：", e)

            # 安全组与规则
            try:
                raw = self.call_api("ecs.aliyuncs.com", "2014-05-26", "DescribeSecurityGroups",
                                    "POST", params={"PageSize": 100}, region_id=region)
                obj = json.loads(raw)
                for sg in obj.get("SecurityGroups", {}).get("SecurityGroup", []):
                    gid = sg.get("SecurityGroupId")
                    rules = {"Ingress": [], "Egress": []}
                    try:
                        raw2 = self.call_api("ecs.aliyuncs.com", "2014-05-26", "DescribeSecurityGroupAttribute",
                                             "POST", params={"SecurityGroupId": gid, "NicType": "intranet"},
                                             region_id=region)
                        o2 = json.loads(raw2)
                        for p in o2.get("Permissions", {}).get("Permission", []):
                            direction = "Ingress" if p.get("Direction", "") == "ingress" else "Egress"
                            rules[direction].append({
                                "IpProtocol": p.get("IpProtocol"),
                                "PortRange": p.get("PortRange"),
                                "SourceCidrIp": p.get("SourceCidrIp",""),
                                "DestCidrIp": p.get("DestCidrIp","")
                            })
                    except Exception:
                        pass
                    self.data["resources"]["ecs"]["security_groups"].append({
                        "RegionId": region, "SecurityGroupId": gid, "SecurityGroupName": sg.get("SecurityGroupName"),
                        "VpcId": sg.get("VpcId"), "Rules": rules
                    })
            except Exception as e:
                print("      ❌ DescribeSecurityGroups：", e)

            # 密钥对
            try:
                raw = self.call_api("ecs.aliyuncs.com", "2014-05-26", "DescribeKeyPairs",
                                    "POST", params={"PageSize": 100}, region_id=region)
                obj = json.loads(raw)
                for kp in obj.get("KeyPairs", {}).get("KeyPair", []):
                    self.data["resources"]["ecs"]["key_pairs"].append({
                        "RegionId": region, "KeyPairName": kp.get("KeyPairName"),
                        "KeyPairFingerPrint": kp.get("KeyPairFingerPrint")
                    })
            except Exception as e:
                print("      ❌ DescribeKeyPairs：", e)

    # ---------------- RDS ----------------
    def enumerate_rds(self):
        print("\n🗄️ RDS（多地域）")
        for region in self.regions:
            print(f"   区域：{region}")
            try:
                raw = self.call_api("rds.aliyuncs.com", "2014-08-15", "DescribeDBInstances",
                                    "POST", params={"PageSize": 100}, region_id=region)
                obj = json.loads(raw)
                for ins in obj.get("Items", {}).get("DBInstance", []):
                    self.data["resources"]["rds"]["instances"].append({
                        "RegionId": region,
                        "DBInstanceId": ins.get("DBInstanceId"),
                        "Engine": ins.get("Engine"),
                        "EngineVersion": ins.get("EngineVersion"),
                        "DBInstanceStatus": ins.get("DBInstanceStatus"),
                        "DBInstanceType": ins.get("DBInstanceType"),
                        "VpcId": ins.get("VpcId"),
                        "VSwitchId": ins.get("VSwitchId"),
                        "PublicConnection": ins.get("ConnectionString") if ins.get("ConnectionMode")=="Public" else ins.get("PublicConnectionString",""),
                        "ConnectionMode": ins.get("ConnectionMode","")
                    })
            except Exception as e:
                print("      ❌ DescribeDBInstances：", e)

    # ---------------- VPC ----------------
    def enumerate_vpc(self):
        print("\n🌐 VPC / 交换机 / 路由表 / NAT（多地域）")
        for region in self.regions:
            print(f"   区域：{region}")
            try:
                raw = self.call_api("vpc.aliyuncs.com", "2016-04-28", "DescribeVpcs",
                                    "POST", params={"PageSize": 100}, region_id=region)
                obj = json.loads(raw)
                for v in obj.get("Vpcs", {}).get("Vpc", []):
                    self.data["resources"]["vpc"]["vpcs"].append({
                        "RegionId": region, "VpcId": v.get("VpcId"),
                        "CidrBlock": v.get("CidrBlock"), "IsDefault": v.get("IsDefault")
                    })
            except Exception as e:
                print("      ❌ DescribeVpcs：", e)
            try:
                raw = self.call_api("vpc.aliyuncs.com", "2016-04-28", "DescribeVSwitches",
                                    "POST", params={"PageSize": 100}, region_id=region)
                obj = json.loads(raw)
                for s in obj.get("VSwitches", {}).get("VSwitch", []):
                    self.data["resources"]["vpc"]["vswitches"].append({
                        "RegionId": region, "VSwitchId": s.get("VSwitchId"),
                        "VpcId": s.get("VpcId"), "CidrBlock": s.get("CidrBlock"),
                        "ZoneId": s.get("ZoneId")
                    })
            except Exception as e:
                print("      ❌ DescribeVSwitches：", e)
            try:
                raw = self.call_api("vpc.aliyuncs.com", "2016-04-28", "DescribeRouteTables",
                                    "POST", params={"PageSize": 50}, region_id=region)
                obj = json.loads(raw)
                for rt in obj.get("RouteTables", {}).get("RouteTable", []):
                    self.data["resources"]["vpc"]["route_tables"].append({
                        "RegionId": region, "RouteTableId": rt.get("RouteTableId"),
                        "VpcId": rt.get("VpcId"), "RouteTableType": rt.get("RouteTableType")
                    })
            except Exception as e:
                print("      ❌ DescribeRouteTables：", e)
            try:
                raw = self.call_api("vpc.aliyuncs.com", "2016-04-28", "DescribeNatGateways",
                                    "POST", params={"PageSize": 50}, region_id=region)
                obj = json.loads(raw)
                for nat in obj.get("NatGateways", {}).get("NatGateway", []):
                    self.data["resources"]["vpc"]["nat_gateways"].append({
                        "RegionId": region, "NatGatewayId": nat.get("NatGatewayId"),
                        "VpcId": nat.get("VpcId"), "Status": nat.get("Status")
                    })
            except Exception as e:
                print("      ❌ DescribeNatGateways：", e)

    # ---------------- KMS ----------------
    def enumerate_kms(self):
        print("\n🔑 KMS（多地域）")
        for region in self.regions:
            print(f"   区域：{region}")
            domain = f"kms.{region}.aliyuncs.com"
            try:
                raw = self.call_api(domain, "2016-01-20", "ListKeys", "POST",
                                    params={"PageSize": 50}, region_id=region)
                obj = json.loads(raw)
                for k in obj.get("Keys", {}).get("Key", []):
                    self.data["resources"]["kms"]["keys"].append({
                        "RegionId": region, "KeyId": k.get("KeyId")
                    })
            except Exception as e:
                print("      ❌ ListKeys：", e)

    # ---------------- ActionTrail ----------------
    def enumerate_actiontrail(self):
        print("\n🧾 ActionTrail (操作审计)")
        try:
            raw = self.call_api("actiontrail.cn-hangzhou.aliyuncs.com", "2017-12-04",
                                "DescribeTrails", "POST")
            obj = json.loads(raw)
            trails = obj.get("TrailList", {}).get("TrailList", []) or obj.get("TrailList", [])
            for t in trails:
                self.data["resources"]["actiontrail"]["trails"].append({
                    "Name": t.get("Name") or t.get("TrailName"),
                    "HomeRegion": t.get("Region") or t.get("HomeRegion"),
                    "OssBucketName": t.get("OssBucketName"),
                    "SlsProjectArn": t.get("SlsProjectArn"),
                    "EventRW": t.get("EventRW")
                })
        except Exception as e:
            print("   ❌ DescribeTrails：", e)

    # ---------------- OSS 权限与全量对象枚举 ----------------
    @staticmethod
    def _normalize_oss_endpoint(region_or_loc: str, fallback_region: str) -> str:
        """
        输入可能是 'oss-cn-beijing' / 'cn-beijing' / 'cn-beijing.aliyuncs.com'
        返回 'https://oss-cn-beijing.aliyuncs.com'
        """
        host = region_or_loc or fallback_region
        if host.startswith("http"):
            return host
        if host.endswith(".aliyuncs.com"):
            ep_host = host
        else:
            if not host.startswith("oss-"):
                host = "oss-" + host
            ep_host = f"{host}.aliyuncs.com"
        return "https://" + ep_host

    def enumerate_oss(self):
        print("\n🪣 OSS 权限与对象枚举（全量）")
        # 使用主 Region 构造服务入口，列出所有桶；每个桶再用其 location 构造 endpoint
        service_ep = self._normalize_oss_endpoint(self.regions[0], self.regions[0])
        auth = oss2.Auth(self.ak, self.sk)

        # 列出 Bucket（扁平化）
        svc = oss2.Service(auth, service_ep)
        buckets = []
        try:
            for b in oss2.BucketIterator(svc):
                name = getattr(b, "name", None); name = name() if callable(name) else name
                loc = getattr(b, "location", None); loc = loc() if callable(loc) else loc
                if name:
                    buckets.append((str(name), (loc or None)))
                    if OSS_MAX_BUCKETS_TO_LIST and len(buckets) >= OSS_MAX_BUCKETS_TO_LIST:
                        break
        except Exception as e:
            print("   ❌ 列举 Bucket 失败：", e)

        if not buckets:
            print("   未发现 Bucket，或权限不足/网络异常。")
            return

        print(f"   发现 Bucket 数量：{len(buckets)}（上限：{OSS_MAX_BUCKETS_TO_LIST or '无'}）")

        # 全量对象 CSV
        all_obj_csv = os.path.join(self.report_dir, "all_objects.csv")
        with open(all_obj_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["bucket", "object_key", "size_bytes", "last_modified"])

            grand_total = 0
            for i, (bname, bloc) in enumerate(buckets, 1):
                ep = self._normalize_oss_endpoint(bloc or self.regions[0], self.regions[0])
                print("\n" + "-"*60)
                print(f"[{i}/{len(buckets)}] Bucket: {bname}   region: {bloc or self.regions[0]}   endpoint: {ep}")

                bucket_cli = oss2.Bucket(auth, ep, bname)

                # ========== 新增：四项权限自测（零副作用） ==========
                can_put_object = False
                can_delete_object = False
                can_get_acl = False
                can_put_acl = False
                acl_val = "Unknown"

                # 1) 获取 ACL（查看权限）
                try:
                    acl = bucket_cli.get_bucket_acl()
                    acl_val = getattr(acl, "acl", "Unknown")
                    can_get_acl = True
                except Exception as e:
                    print(f"  ⚠️ 获取 ACL 失败：{e}")

                # 2) PutBucketAcl 幂等回写（修改 ACL 权限探测，不改变现状）
                if can_get_acl and acl_val not in (None, "", "Unknown"):
                    try:
                        bucket_cli.put_bucket_acl(acl_val)  # 原样回写
                        can_put_acl = True
                    except Exception:
                        can_put_acl = False

                # 3) PutObject：上传一个极小的临时对象
                temp_key = f"__perm_probe__/{int(time.time()*1000)}_{os.getpid()}.txt"
                try:
                    bucket_cli.put_object(temp_key, b"probe")
                    can_put_object = True
                except Exception:
                    can_put_object = False

                # 4) DeleteObject：删除刚才的临时对象（若 Put 成功应能删；若 Put 失败仍尝试）
                try:
                    bucket_cli.delete_object(temp_key)
                    can_delete_object = True
                except Exception:
                    can_delete_object = False

                # 打印权限结果
                print(f"  权限自测：PutObject={'✅' if can_put_object else '❌'} | "
                      f"DeleteObject={'✅' if can_delete_object else '❌'} | "
                      f"GetACL={'✅' if can_get_acl else '❌'} | PutACL(幂等)={'✅' if can_put_acl else '❌'}")
                # ===============================================

                # 列举对象（marker 分页）
                total = 0
                try:
                    marker, max_keys = "", 1000
                    start = time.time()
                    while True:
                        resp = bucket_cli.list_objects(marker=marker, max_keys=max_keys)
                        objs = getattr(resp, "object_list", []) or []
                        for o in objs:
                            total += 1
                            writer.writerow([bname, o.key, o.size, o.last_modified])
                            if total % OSS_PROGRESS_INTERVAL == 0:
                                print(f"    {bname}: 已列举 {total} 个对象，用时 {time.time()-start:.1f}s")
                        if getattr(resp, "is_truncated", False):
                            marker = getattr(resp, "next_marker", "") or (objs[-1].key if objs else "")
                        else:
                            break
                    print(f"  -> {bname} 对象数量: {total}")
                except oss2.exceptions.ClientError as ce:
                    print(f"  ⚠️ 访问失败（ClientError）：{ce}")
                except Exception as e:
                    print(f"  ⚠️ 异常：{e}")

                grand_total += total
                # 记录到资源清单（包含四项权限结果）
                self.data["resources"]["oss"]["buckets"].append({
                    "bucket": bname,
                    "region": bloc or self.regions[0],
                    "endpoint": ep,
                    "acl": acl_val,
                    "object_count": total,
                    "can_put_object": can_put_object,
                    "can_delete_object": can_delete_object,
                    "can_get_acl": can_get_acl,
                    "can_put_acl": can_put_acl
                })

                # 基于 ACL 的风险识别（原逻辑不变）
                if acl_val == "public-read-write":
                    self.data["risks"]["critical"].append({
                        "type": "OSS_BUCKET_PUBLIC_READ_WRITE",
                        "resource": bname,
                        "description": "Bucket 为 public-read-write（严重安全风险）",
                        "recommendation": "立即改为私有或最小必要权限；通过 CDN/STS 临时授权对外"
                    })
                elif acl_val == "public-read":
                    self.data["risks"]["high"].append({
                        "type": "OSS_BUCKET_PUBLIC_READ",
                        "resource": bname,
                        "description": "Bucket 为 public-read（对外可读）",
                        "recommendation": "确认业务必要性；否则改为私有并使用 CDN 或签名 URL"
                    })

            self.data["resources"]["oss"]["grand_total_objects"] = grand_total
            print("\n" + "="*60)
            print(f"   所有 Bucket 对象总数：{grand_total}")
            print(f"   明细已写入：{all_obj_csv}")

        # 额外输出一个桶级 CSV（保持原样字段，不新增列）
        oss_csv = os.path.join(self.report_dir, "oss_buckets.csv")
        with open(oss_csv, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["bucket", "region", "endpoint", "acl", "object_count"])
            w.writeheader()
            for b in self.data["resources"]["oss"]["buckets"]:
                w.writerow({k: b.get(k, "") for k in ["bucket", "region", "endpoint", "acl", "object_count"]})
        print(f"💾 CSV：{oss_csv}")

    # ---------------- 风险分析（复用） ----------------
    def analyze_risks(self):
        print("\n🚨 风险分析")
        risks = self.data["risks"]

        # ECS 安全组
        for sg in self.data["resources"]["ecs"]["security_groups"]:
            gid = sg["SecurityGroupId"]
            rules = sg["Rules"].get("Ingress", [])
            for r in rules:
                src = r.get("SourceCidrIp", "")
                prange = r.get("PortRange", "all")
                if src in ("0.0.0.0/0", "::/0"):
                    def port_hit(pr):
                        if pr in ("-1/-1", "all"): return True
                        try:
                            start, end = pr.split("/")
                            return int(start) in (22, 3389, 1433, 3306, 5432)
                        except Exception:
                            return False
                    if port_hit(prange):
                        risks["critical"].append({
                            "type": "SG_DANGEROUS_PUBLIC_INBOUND",
                            "resource": gid,
                            "description": f"安全组允许 {src} 访问高危端口 {prange}",
                            "recommendation": "限制源到固定出口 IP 或使用堡垒/SSM"
                        })
                    elif prange not in ("80/80","443/443"):
                        risks["high"].append({
                            "type": "SG_PUBLIC_INBOUND",
                            "resource": gid,
                            "description": f"安全组对公网开放端口 {prange}",
                            "recommendation": "按需收敛，避免 0.0.0.0/0"
                        })

        # ECS 公网
        for ins in self.data["resources"]["ecs"]["instances"]:
            if ins.get("PublicIp") or ins.get("EipAddress"):
                risks["medium"].append({
                    "type": "ECS_PUBLIC_IP",
                    "resource": ins["InstanceId"],
                    "description": "ECS 实例存在公网 IP",
                    "recommendation": "仅在必要场景使用公网 IP，优先走 NAT/SLB"
                })

        # RDS 公网
        for db in self.data["resources"]["rds"]["instances"]:
            if db.get("PublicConnection") or db.get("ConnectionMode") == "Public":
                risks["critical"].append({
                    "type": "RDS_PUBLIC_CONNECTION",
                    "resource": db["DBInstanceId"],
                    "description": "RDS 存在公网连接",
                    "recommendation": "关闭公网连接，仅私网访问"
                })

        # ActionTrail 未配置
        if not self.data["resources"]["actiontrail"]["trails"]:
            risks["high"].append({
                "type": "ACTIONTRAIL_NOT_CONFIGURED",
                "resource": "ActionTrail",
                "description": "未检测到操作审计 Trail",
                "recommendation": "启用 ActionTrail 并投递到 SLS/OSS"
            })

    # ---------------- 统计/评分/建议 ----------------
    def build_stats_and_assessment(self):
        res = self.data["resources"]
        stats = {
            "ecs_instances": len(res["ecs"]["instances"]),
            "ecs_security_groups": len(res["ecs"]["security_groups"]),
            "ecs_key_pairs": len(res["ecs"]["key_pairs"]),
            "rds_instances": len(res["rds"]["instances"]),
            "vpcs": len(res["vpc"]["vpcs"]),
            "vswitches": len(res["vpc"]["vswitches"]),
            "route_tables": len(res["vpc"]["route_tables"]),
            "nat_gateways": len(res["vpc"]["nat_gateways"]),
            "kms_keys": len(res["kms"]["keys"]),
            "ram_users": len(res["ram"].get("users", [])),
            "ram_roles": len(res["ram"].get("roles", [])),
            "action_trails": len(res["actiontrail"]["trails"]),
            "oss_buckets": len(res["oss"]["buckets"]),
            "oss_objects_total": res["oss"]["grand_total_objects"],
        }
        self.data["stats"] = stats

        r = self.data["risks"]
        score = len(r["critical"])*10 + len(r["high"])*5 + len(r["medium"])*2 + len(r["low"])*1
        if score >= 50: level = "🔥 极高风险 (CRITICAL)"
        elif score >= 30: level = "🚨 高风险 (HIGH)"
        elif score >= 15: level = "⚠️ 中等风险 (MEDIUM)"
        else: level = "ℹ️ 低风险 (LOW)"

        self.data["assessment"] = {
            "risk_score": score,
            "risk_level": level,
            "risk_breakdown": {k: len(v) for k,v in r.items()},
            "recommendations": self._recommendations()
        }

    def _recommendations(self):
        rs = [it["type"] for k in self.data["risks"] for it in self.data["risks"][k]]
        recs = []
        if "ROOT_CREDENTIAL_IN_USE" in rs:
            recs.append({"title": "停用 root AK/SK", "priority": "CRITICAL",
                         "items": ["新建 RAM 管理员并启用 MFA", "使用最小权限与 STS 临时凭证"]})
        if "OSS_BUCKET_PUBLIC_READ_WRITE" in rs or "OSS_BUCKET_PUBLIC_READ" in rs:
            recs.append({"title": "OSS 公共访问收敛", "priority": "HIGH",
                         "items": ["改为私有或签名 URL/STS 临时授权", "必要对外场景使用 CDN"]})
        if "SG_DANGEROUS_PUBLIC_INBOUND" in rs:
            recs.append({"title": "收敛安全组高危端口", "priority": "CRITICAL",
                         "items": ["限制 22/3389/数据库端口到固定源 IP", "引入堡垒机或 SSM"]})
        if "RDS_PUBLIC_CONNECTION" in rs:
            recs.append({"title": "关闭 RDS 公网连接", "priority": "HIGH",
                         "items": ["仅通过私网访问", "专线/VPN 或跳板服务器"]})
        if "ACTIONTRAIL_NOT_CONFIGURED" in rs:
            recs.append({"title": "开启 ActionTrail 审计", "priority": "HIGH",
                         "items": ["投递到 SLS/OSS", "设置检索与告警"]})
        return recs

    # ---------------- 报告输出 ----------------
    def save_json(self):
        path = os.path.join(self.report_dir, "audit_report.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, ensure_ascii=False, indent=2)
        print(f"💾 JSON：{path}")

    def save_csv(self):
        # ECS 实例
        ins = self.data["resources"]["ecs"]["instances"]
        if ins:
            path = os.path.join(self.report_dir, "ecs_instances.csv")
            with open(path, "w", newline="", encoding="utf-8") as f:
                fields = ["InstanceId","InstanceName","RegionId","ZoneId","Status","VpcId","VSwitchId","PrivateIp","PublicIp","EipAddress"]
                w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
                for x in ins: w.writerow({k: x.get(k,"") for k in fields})
            print(f"💾 CSV：{path}")

        # 安全组
        sgs = self.data["resources"]["ecs"]["security_groups"]
        if sgs:
            path = os.path.join(self.report_dir, "ecs_security_groups.csv")
            with open(path, "w", newline="", encoding="utf-8") as f:
                fields = ["RegionId","SecurityGroupId","SecurityGroupName","VpcId","IngressRules","EgressRules"]
                w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
                for sg in sgs:
                    ing = json.dumps(sg["Rules"].get("Ingress", []), ensure_ascii=False)
                    egr = json.dumps(sg["Rules"].get("Egress", []), ensure_ascii=False)
                    row = {
                        "RegionId": sg["RegionId"], "SecurityGroupId": sg["SecurityGroupId"],
                        "SecurityGroupName": sg.get("SecurityGroupName",""), "VpcId": sg.get("VpcId",""),
                        "IngressRules": ing, "EgressRules": egr
                    }
                    w.writerow(row)
            print(f"💾 CSV：{path}")

        # RDS
        rds = self.data["resources"]["rds"]["instances"]
        if rds:
            path = os.path.join(self.report_dir, "rds_instances.csv")
            with open(path, "w", newline="", encoding="utf-8") as f:
                fields = ["RegionId","DBInstanceId","Engine","EngineVersion","DBInstanceStatus","DBInstanceType","VpcId","VSwitchId","PublicConnection","ConnectionMode"]
                w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
                for x in rds: w.writerow({k: x.get(k,"") for k in fields})
            print(f"💾 CSV：{path}")

        # VPC
        vpcs = self.data["resources"]["vpc"]["vpcs"]
        if vpcs:
            path = os.path.join(self.report_dir, "vpc_vpcs.csv")
            with open(path, "w", newline="", encoding="utf-8") as f:
                fields = ["RegionId","VpcId","CidrBlock","IsDefault"]
                w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
                for x in vpcs: w.writerow({k: x.get(k,"") for k in fields})
            print(f"💾 CSV：{path}")

        # OSS 桶级 CSV（对象明细在 enumerate_oss 时已生成 all_objects.csv）
        oss_buckets = self.data["resources"]["oss"]["buckets"]
        if oss_buckets:
            path = os.path.join(self.report_dir, "oss_buckets.csv")
            with open(path, "w", newline="", encoding="utf-8") as f:
                fields = ["bucket","region","endpoint","acl","object_count"]
                w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
                for b in oss_buckets: w.writerow({k: b.get(k,"") for k in fields})
            print(f"💾 CSV：{path}")

    def save_html(self):
        s = self.data["stats"]
        risks = self.data["risks"]
        assess = self.data["assessment"]
        ident = self.data["identity"]

        def risk_block(title, items, css):
            if not items: return ""
            html = f"<h3>{title} ({len(items)})</h3>"
            for r in items:
                html += f"""
                <div style="border-left:5px solid {css};background:#fff;border:1px solid #eee;border-radius:6px;padding:10px;margin:8px 0">
                  <div><b>{r['type']}</b> — <span style="font-family:Consolas,monospace">{r['resource']}</span></div>
                  <div>{r['description']}</div>
                  <div style="background:#f8f9fa;padding:6px;border-radius:6px;margin-top:6px">建议：{r['recommendation']}</div>
                </div>"""
            return html

        # 小工具：把布尔转成图标
        def b2i(v):
            return "✅" if v else "❌"

        # 构造权限表格 HTML（前 50）
        oss_perm_rows = []
        for b in self.data['resources']['oss']['buckets'][:50]:
            oss_perm_rows.append(
                f"<tr>"
                f"<td class='code'>{b.get('bucket')}</td>"
                f"<td>{b2i(b.get('can_put_object'))}</td>"
                f"<td>{b2i(b.get('can_delete_object'))}</td>"
                f"<td>{b2i(b.get('can_get_acl'))}</td>"
                f"<td>{b2i(b.get('can_put_acl'))}</td>"
                f"</tr>"
            )

        html = f"""<!DOCTYPE html><html lang="zh-CN"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>阿里云 AK/SK 鉴定与审计报告</title>
<style>
body{{font-family:Arial,Helvetica,sans-serif;background:#f5f7fa;margin:0;padding:20px;}}
.container{{max-width:1200px;margin:0 auto;}}
.header{{background:linear-gradient(135deg,#1f2d3d,#00a3ff);color:#fff;padding:24px;border-radius:12px;}}
.card{{background:#fff;border:1px solid #e9ecef;border-radius:10px;padding:14px;margin-top:14px}}
.table table{{width:100%;border-collapse:collapse}}
.table th,.table td{{padding:8px;border-bottom:1px solid #eee;text-align:left}}
.badge{{display:inline-block;padding:4px 8px;border-radius:10px;font-weight:bold;font-size:12px}}
.b-crit{{background:#ffe6e6;color:#a61b1b}} .b-warn{{background:#fff5cc;color:#8a6d3b}} .b-info{{background:#e6f2ff;color:#0b63b5}}
.code{{font-family:Consolas,monospace;background:#f3f4f6;padding:2px 6px;border-radius:4px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}}
.subtle{{color:#666;margin:6px 0 0 0;font-size:13px}}
</style></head><body><div class="container">
<div class="header"><h1>阿里云 AK/SK 鉴定与审计报告</h1>
<p>生成时间：{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
<p>身份：AccountId={ident.get('AccountId','?')} | Arn=<span class="code">{ident.get('Arn','?')}</span></p>
</div>

<div class="grid">
  <div class="card"><h3>资源统计</h3>
    <p>OSS 桶：<b>{s.get('oss_buckets',0)}</b>（对象总数：<b>{s.get('oss_objects_total',0)}</b>）</p>
    <p>ECS 实例：<b>{s.get('ecs_instances',0)}</b>，安全组：<b>{s.get('ecs_security_groups',0)}</b></p>
    <p>RDS 实例：<b>{s.get('rds_instances',0)}</b>，VPC：<b>{s.get('vpcs',0)}</b></p>
    <p>KMS Keys：<b>{s.get('kms_keys',0)}</b>，RAM 用户/角色：<b>{s.get('ram_users',0)}</b>/<b>{s.get('ram_roles',0)}</b></p>
  </div>
  <div class="card"><h3>风险评分</h3>
    <p>总分：<b>{assess.get('risk_score',0)}</b></p>
    <p>等级：<span class="badge {'b-crit' if 'CRITICAL' in assess.get('risk_level','') else 'b-warn' if 'HIGH' in assess.get('risk_level','') else 'b-info'}">{assess.get('risk_level','')}</span></p>
    <p>分布：严重 {len(risks['critical'])} / 高 {len(risks['high'])} / 中 {len(risks['medium'])} / 低 {len(risks['low'])}</p>
  </div>
</div>

<div class="card">
  <h2>风险详情</h2>
  {risk_block("🔥 严重风险", risks["critical"], "#e53935")}
  {risk_block("🚨 高风险", risks["high"], "#fb8c00")}
  {risk_block("⚠️ 中风险", risks["medium"], "#f1c40f")}
  {risk_block("ℹ️ 低风险/信息", risks["low"]+risks.get("info",[]), "#5dade2")}
</div>

<div class="card table">
  <h2>🪣 OSS 桶（前 50）</h2>
  <table><tr><th>Bucket</th><th>Region</th><th>Endpoint</th><th>ACL</th><th>Objects</th></tr>
  {"".join([f"<tr><td class='code'>{b.get('bucket')}</td><td>{b.get('region')}</td><td class='code'>{b.get('endpoint')}</td><td>{b.get('acl')}</td><td>{b.get('object_count')}</td></tr>" for b in self.data['resources']['oss']['buckets'][:50]])}
  </table>

  <h3 style="margin-top:18px">🔐 权限自测（前 50）</h3>
  <p class="subtle">说明：PutACL 显示为“幂等回写”探测，不改变原 ACL；临时对象会立即删除，不影响业务。</p>
  <table>
    <tr>
      <th>Bucket</th><th>PutObject</th><th>DeleteObject</th><th>GetACL</th><th>PutACL(幂等)</th>
    </tr>
    {"".join(oss_perm_rows)}
  </table>

  <p style="margin-top:8px">对象明细：<span class="code">all_objects.csv</span></p>
</div>

<div class="card table">
  <h2>💻 ECS 实例（前 50）</h2>
  <table><tr><th>ID</th><th>名称</th><th>状态</th><th>地域</th><th>私网IP</th><th>公网IP/EIP</th></tr>
  {"".join([f"<tr><td class='code'>{x.get('InstanceId')}</td><td>{x.get('InstanceName','')}</td><td>{x.get('Status','')}</td><td>{x.get('RegionId')}</td><td>{x.get('PrivateIp','')}</td><td>{x.get('PublicIp','') or x.get('EipAddress','')}</td></tr>" for x in self.data['resources']['ecs']['instances'][:50]])}
  </table>
</div>

<div class="card table">
  <h2>RDS 实例（前 30）</h2>
  <table><tr><th>ID</th><th>引擎</th><th>版本</th><th>连接模式</th><th>公网连接</th></tr>
  {"".join([f"<tr><td class='code'>{x.get('DBInstanceId')}</td><td>{x.get('Engine')}</td><td>{x.get('EngineVersion')}</td><td>{x.get('ConnectionMode','')}</td><td>{x.get('PublicConnection','') or '-'}</td></tr>" for x in self.data['resources']['rds']['instances'][:30]])}
  </table>
</div>

</div></body></html>"""
        path = os.path.join(self.report_dir, "audit_report.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"🌐 HTML：{path}")

    # ---------------- 主流程 ----------------
    def run(self, do_nls=False):
        self.test_identity()
        if do_nls:
            self.optional_nls_token_test()
        self.enumerate_ram()
        self.enumerate_ecs()
        self.enumerate_rds()
        self.enumerate_vpc()
        self.enumerate_kms()
        self.enumerate_actiontrail()
        self.enumerate_oss()             # ✅ 已加入权限自测且零副作用
        self.analyze_risks()
        self.build_stats_and_assessment()
        self.save_json()
        self.save_csv()
        self.save_html()

        print("\n🎯 鉴定完成")
        print(f"   报告：{self.report_dir}/audit_report.html")
        print(f"   详情：{self.report_dir}/audit_report.json")
        print(f"   CSV：{self.report_dir}/*.csv（含 all_objects.csv）")

# ========= 入口 =========
def main():
    print("🚀 阿里云 AK/SK 鉴定与只读审计工具（含 OSS）")
    print("="*60)
    ak = os.getenv("ALIYUN_ACCESS_KEY_ID") or input("AccessKeyId: ").strip()
    sk = os.getenv("ALIYUN_ACCESS_KEY_SECRET") or input("AccessKeySecret: ").strip()
    if not ak or not sk:
        print("❌ AK/SK 不能为空"); sys.exit(1)

    print("\n🌍 选择地域（逗号分隔，留空默认）：", ", ".join(DEFAULT_REGIONS))
    reg_in = input("Regions: ").strip()
    regions = [r.strip() for r in reg_in.split(",") if r.strip()] if reg_in else None
    print(f"✅ 将在以下地域尝试枚举：{', '.join(regions or DEFAULT_REGIONS)}")

    do_nls = input("进行 NLS CreateToken 测试？(y/N): ").strip().lower() == "y"

    try:
        auditor = AliyunAuditor(ak, sk, regions)
        auditor.run(do_nls=do_nls)
    except KeyboardInterrupt:
        print("\n⚠️ 已中断")
    except Exception as e:
        print("\n❌ 运行失败：", e)
        traceback.print_exc()

if __name__ == "__main__":
    main()

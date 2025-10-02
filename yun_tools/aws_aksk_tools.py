#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AWS综合安全审计工具 - 合并增强版（无密钥）
"""
import boto3
import json
import csv
import os
import time
import sys
import traceback
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError

class AWSComprehensiveAuditor:
    def __init__(self, access_key_id, secret_access_key, regions=None):
        """初始化AWS审计工具"""
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.regions = regions or ['us-east-1', 'us-west-2', 'ap-northeast-1']
        self.session = boto3.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key
        )
        # 创建报告目录
        self.report_dir = f"aws_comprehensive_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(self.report_dir, exist_ok=True)

        # 存储所有收集的数据
        self.audit_data = {
            'identity': {},
            'permissions': {},
            'permission_details': {},
            'resources': {},
            'security_analysis': {},
            'risk_assessment': {},
            'dangerous_tests': {}
        }

        print(f"📁 报告将保存到: {self.report_dir}/")

    def get_client(self, service, region='us-east-1'):
        """获取AWS服务客户端"""
        return boto3.client(
            service,
            aws_access_key_id=self.access_key_id,
            aws_secret_access_key=self.secret_access_key,
            region_name=region
        )

    # ========= 身份与权限 =========
    def test_identity_and_permissions(self):
        """测试身份和基础只读权限"""
        print("=" * 80)
        print("🔍 身份验证和权限测试")
        print("=" * 80)
        try:
            sts = self.get_client('sts')
            identity = sts.get_caller_identity()
            self.audit_data['identity'] = {
                'account_id': identity.get('Account'),
                'user_id': identity.get('UserId'),
                'arn': identity.get('Arn'),
                'test_time': datetime.now().isoformat()
            }
            print("✅ 身份验证成功")
            print(f"   账户ID: {identity.get('Account')}")
            print(f"   用户ID: {identity.get('UserId')}")
            print(f"   ARN: {identity.get('Arn')}")
            self._test_service_permissions()
            return True
        except Exception as e:
            print(f"❌ 身份验证失败: {e}")
            return False

    def _test_service_permissions(self):
        """枚举可用的只读权限（最小调用）"""
        print("\n🧪 权限枚举测试...")
        services_to_test = [
            ('iam', 'list_users', {}, 'IAM用户列表'),
            ('iam', 'list_roles', {}, 'IAM角色列表'),
            ('iam', 'list_policies', {'Scope': 'Local'}, 'IAM策略列表'),
            ('iam', 'get_account_summary', {}, 'IAM账户摘要'),
            ('s3', 'list_buckets', {}, 'S3存储桶列表'),
            ('ec2', 'describe_instances', {}, 'EC2实例列表'),
            ('ec2', 'describe_security_groups', {}, '安全组列表'),
            ('ec2', 'describe_vpcs', {}, 'VPC(虚拟私有云)列表'),
            ('ec2', 'describe_subnets', {}, '子网列表'),
            ('ec2', 'describe_key_pairs', {}, 'SSH密钥对'),
            ('lambda', 'list_functions', {}, 'Lambda函数'),
            ('rds', 'describe_db_instances', {}, 'RDS实例'),
            ('dynamodb', 'list_tables', {}, 'DynamoDB表'),
            ('route53', 'list_hosted_zones', {}, 'Route53托管区域'),
            ('cloudtrail', 'describe_trails', {}, 'CloudTrail'),
            ('config', 'describe_configuration_recorders', {}, 'Config记录器'),
            ('organizations', 'describe_organization', {}, 'AWS组织信息'),
            ('organizations', 'list_accounts', {}, '组织账户列表'),
            ('secretsmanager', 'list_secrets', {'MaxResults': 50}, 'Secrets Manager'),
            ('ssm', 'describe_parameters', {'MaxResults': 50}, 'Systems Manager参数'),
            ('logs', 'describe_log_groups', {'limit': 50}, 'CloudWatch日志组'),
            # CloudWatch 列表指标无需多余参数，避免参数校验错误
            ('cloudwatch', 'list_metrics', {}, 'CloudWatch指标'),
        ]

        permission_results = {}
        successful_count = 0

        for service_name, method_name, params, description in services_to_test:
            try:
                client = self.get_client(service_name)
                method = getattr(client, method_name)
                response = method(**params)
                print(f"✅ {service_name}.{method_name} - {description}")
                permission_results[f"{service_name}.{method_name}"] = "SUCCESS"
                successful_count += 1
                self._store_permission_result(service_name, method_name, response)
            except ClientError as e:
                error_code = e.response['Error']['Code']
                print(f"❌ {service_name}.{method_name} - 失败: {error_code}")
                permission_results[f"{service_name}.{method_name}"] = error_code
            except Exception as e:
                print(f"❌ {service_name}.{method_name} - 错误: {str(e)}")
                permission_results[f"{service_name}.{method_name}"] = str(e)

        self.audit_data['permissions'] = {
            'results': permission_results,
            'successful_count': successful_count,
            'total_tests': len(services_to_test),
            'success_rate': f"{(successful_count/len(services_to_test))*100:.1f}%"
        }
        print(f"\n📊 权限测试完成: {successful_count}/{len(services_to_test)} 个权限可用")

    def _store_permission_result(self, service_name, method_name, response):
        """存储权限测试关键数据"""
        key = f"{service_name}.{method_name}"
        if service_name == 'iam' and method_name == 'list_users':
            self.audit_data['permission_details'][key] = {
                'count': len(response.get('Users', [])),
                'users': [user['UserName'] for user in response.get('Users', [])]
            }
        elif service_name == 'iam' and method_name == 'list_roles':
            self.audit_data['permission_details'][key] = {
                'count': len(response.get('Roles', [])),
                'roles': [role['RoleName'] for role in response.get('Roles', [])]
            }
        elif service_name == 's3' and method_name == 'list_buckets':
            self.audit_data['permission_details'][key] = {
                'count': len(response.get('Buckets', [])),
                'buckets': [b['Name'] for b in response.get('Buckets', [])]
            }
        elif service_name == 'organizations' and method_name == 'list_accounts':
            self.audit_data['permission_details'][key] = {
                'count': len(response.get('Accounts', [])),
                'accounts': [{'id': a['Id'], 'name': a['Name'], 'email': a['Email']}
                             for a in response.get('Accounts', [])]
            }

    # ========= 资源枚举 =========
    def enumerate_all_resources(self):
        """枚举所有AWS资源"""
        print("\n" + "=" * 80)
        print("📦 AWS资源详细枚举")
        print("=" * 80)
        self._enumerate_s3_resources()
        self._enumerate_ec2_resources()
        self._enumerate_iam_resources()
        self._enumerate_database_resources()
        self._enumerate_lambda_resources()
        self._enumerate_network_resources()
        self._enumerate_security_resources()
        self._enumerate_organization_resources()

    def _enumerate_s3_resources(self):
        """S3详细枚举（版本、加密、公共访问、对象采样与容量）"""
        print("\n🪣 S3存储桶详细枚举...")
        s3_data = {'buckets': [], 'total_objects': 0, 'total_size': 0}
        try:
            s3_client = self.get_client('s3')
            response = s3_client.list_buckets()
            buckets = response.get('Buckets', [])
            print(f"   发现 {len(buckets)} 个存储桶")
            for i, bucket in enumerate(buckets, 1):
                bucket_name = bucket['Name']
                print(f"   [{i}/{len(buckets)}] 分析存储桶: {bucket_name}")
                info = {
                    'name': bucket_name,
                    'creation_date': bucket['CreationDate'].isoformat(),
                    'region': 'us-east-1',
                    'objects': [],
                    'total_size': 0,
                    'object_count': 0,
                    'security_config': {}
                }
                try:
                    location = s3_client.get_bucket_location(Bucket=bucket_name)
                    info['region'] = location.get('LocationConstraint') or 'us-east-1'
                    # 版本
                    try:
                        versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                        info['security_config']['versioning'] = versioning.get('Status', 'Disabled')
                    except:
                        info['security_config']['versioning'] = 'Unknown'
                    # 加密
                    try:
                        s3_client.get_bucket_encryption(Bucket=bucket_name)
                        info['security_config']['encryption'] = 'Enabled'
                    except:
                        info['security_config']['encryption'] = 'Disabled'
                    # 公共访问
                    try:
                        pab = s3_client.get_public_access_block(Bucket=bucket_name)
                        cfg = pab.get('PublicAccessBlockConfiguration', {})
                        info['security_config']['public_access_blocked'] = all([
                            cfg.get('BlockPublicAcls', False),
                            cfg.get('BlockPublicPolicy', False),
                            cfg.get('IgnorePublicAcls', False),
                            cfg.get('RestrictPublicBuckets', False)
                        ])
                    except:
                        info['security_config']['public_access_blocked'] = False
                    # 对象采样
                    try:
                        objs = s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=1000)
                        if 'Contents' in objs:
                            for obj in objs['Contents']:
                                info['objects'].append({
                                    'key': obj['Key'],
                                    'size': obj['Size'],
                                    'last_modified': obj['LastModified'].isoformat(),
                                    'storage_class': obj.get('StorageClass', 'STANDARD')
                                })
                                info['total_size'] += obj['Size']
                                info['object_count'] += 1
                    except Exception as e:
                        print(f"      ⚠️  无法列出对象: {e}")
                    print(f"      对象数量: {info['object_count']}")
                    print(f"      总大小: {self._format_size(info['total_size'])}")
                    print(f"      加密状态: {info['security_config']['encryption']}")
                    print(f"      公共访问阻止: {info['security_config']['public_access_blocked']}")
                except Exception as e:
                    print(f"      ❌ 处理存储桶失败: {e}")
                s3_data['buckets'].append(info)
                s3_data['total_objects'] += info['object_count']
                s3_data['total_size'] += info['total_size']
            print(f"\n   📊 S3汇总: {len(buckets)}个桶, {s3_data['total_objects']}个对象, {self._format_size(s3_data['total_size'])}")
        except Exception as e:
            print(f"   ❌ S3枚举失败: {e}")
        self.audit_data['resources']['s3'] = s3_data

    def _enumerate_ec2_resources(self):
        """枚举EC2实例/安全组/VPC/密钥对"""
        print("\n💻 EC2资源详细枚举...")
        ec2_data = {'instances': [], 'security_groups': [], 'vpcs': [], 'key_pairs': []}
        for region in self.regions:
            print(f"   🌍 区域: {region}")
            try:
                ec2_client = self.get_client('ec2', region)
                # 实例
                instances_response = ec2_client.describe_instances()
                region_instances = []
                for reservation in instances_response.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        region_instances.append({
                            'instance_id': instance['InstanceId'],
                            'instance_type': instance['InstanceType'],
                            'state': instance['State']['Name'],
                            'launch_time': instance.get('LaunchTime', '').isoformat() if instance.get('LaunchTime') else '',
                            'private_ip': instance.get('PrivateIpAddress', ''),
                            'public_ip': instance.get('PublicIpAddress', ''),
                            'vpc_id': instance.get('VpcId', ''),
                            'subnet_id': instance.get('SubnetId', ''),
                            'key_name': instance.get('KeyName', ''),
                            'security_groups': [sg['GroupId'] for sg in instance.get('SecurityGroups', [])],
                            'tags': {t['Key']: t['Value'] for t in instance.get('Tags', [])} if instance.get('Tags') else {},
                            'region': region
                        })
                print(f"      EC2实例: {len(region_instances)}")
                ec2_data['instances'].extend(region_instances)
                # 安全组
                sgs_response = ec2_client.describe_security_groups()
                for sg in sgs_response['SecurityGroups']:
                    item = {
                        'group_id': sg['GroupId'],
                        'group_name': sg['GroupName'],
                        'description': sg['Description'],
                        'vpc_id': sg.get('VpcId', ''),
                        'region': region,
                        'inbound_rules': [],
                        'outbound_rules': []
                    }
                    for rule in sg.get('IpPermissions', []):
                        item['inbound_rules'].append({
                            'protocol': rule['IpProtocol'],
                            'from_port': rule.get('FromPort', 'All'),
                            'to_port': rule.get('ToPort', 'All'),
                            'ip_ranges': [ip['CidrIp'] for ip in rule.get('IpRanges', [])],
                            'security_groups': [ref['GroupId'] for ref in rule.get('UserIdGroupPairs', [])]
                        })
                    for rule in sg.get('IpPermissionsEgress', []):
                        item['outbound_rules'].append({
                            'protocol': rule['IpProtocol'],
                            'from_port': rule.get('FromPort', 'All'),
                            'to_port': rule.get('ToPort', 'All'),
                            'ip_ranges': [ip['CidrIp'] for ip in rule.get('IpRanges', [])],
                            'security_groups': [ref['GroupId'] for ref in rule.get('UserIdGroupPairs', [])]
                        })
                    ec2_data['security_groups'].append(item)
                # VPC
                vpcs_response = ec2_client.describe_vpcs()
                for vpc in vpcs_response['Vpcs']:
                    ec2_data['vpcs'].append({
                        'vpc_id': vpc['VpcId'],
                        'state': vpc['State'],
                        'cidr_block': vpc['CidrBlock'],
                        'is_default': vpc.get('IsDefault', False),
                        'region': region,
                        'tags': {t['Key']: t['Value'] for t in vpc.get('Tags', [])} if vpc.get('Tags') else {}
                    })
                # 密钥对
                keypairs_response = ec2_client.describe_key_pairs()
                for kp in keypairs_response['KeyPairs']:
                    ec2_data['key_pairs'].append({
                        'key_name': kp['KeyName'],
                        'key_fingerprint': kp['KeyFingerprint'],
                        'key_type': kp.get('KeyType', 'rsa'),
                        'region': region
                    })
                print(f"      安全组: {len([sg for sg in ec2_data['security_groups'] if sg['region'] == region])}")
                print(f"      VPC: {len([v for v in ec2_data['vpcs'] if v['region'] == region])}")
                print(f"      密钥对: {len([k for k in ec2_data['key_pairs'] if k['region'] == region])}")
            except Exception as e:
                print(f"      ❌ 区域 {region} EC2枚举失败: {e}")
        print(f"   📊 EC2汇总: {len(ec2_data['instances'])}实例, {len(ec2_data['security_groups'])}安全组, {len(ec2_data['vpcs'])}个VPC")
        self.audit_data['resources']['ec2'] = ec2_data

    def _enumerate_iam_resources(self):
        """枚举IAM用户/角色/自定义策略（含密钥与策略清单）"""
        print("\n🆔 IAM资源详细枚举...")
        iam_data = {'users': [], 'roles': [], 'policies': [], 'groups': []}
        try:
            iam_client = self.get_client('iam')
            # 用户
            users_paginator = iam_client.get_paginator('list_users')
            for page in users_paginator.paginate():
                for user in page['Users']:
                    info = {
                        'username': user['UserName'],
                        'user_id': user['UserId'],
                        'arn': user['Arn'],
                        'create_date': user['CreateDate'].isoformat(),
                        'password_last_used': user.get('PasswordLastUsed', '').isoformat() if user.get('PasswordLastUsed') else 'Never',
                        'access_keys': [],
                        'attached_policies': [],
                        'inline_policies': [],
                        'groups': []
                    }
                    try:
                        keys = iam_client.list_access_keys(UserName=user['UserName'])
                        for key in keys['AccessKeyMetadata']:
                            info['access_keys'].append({
                                'access_key_id': key['AccessKeyId'],
                                'status': key['Status'],
                                'create_date': key['CreateDate'].isoformat()
                            })
                    except:
                        pass
                    try:
                        pols = iam_client.list_attached_user_policies(UserName=user['UserName'])
                        info['attached_policies'] = [p['PolicyName'] for p in pols['AttachedPolicies']]
                    except:
                        pass
                    try:
                        inlines = iam_client.list_user_policies(UserName=user['UserName'])
                        info['inline_policies'] = inlines['PolicyNames']
                    except:
                        pass
                    try:
                        groups = iam_client.list_groups_for_user(UserName=user['UserName'])
                        info['groups'] = [g['GroupName'] for g in groups['Groups']]
                    except:
                        pass
                    iam_data['users'].append(info)
            # 角色
            roles_paginator = iam_client.get_paginator('list_roles')
            for page in roles_paginator.paginate():
                for role in page['Roles']:
                    r = {
                        'role_name': role['RoleName'],
                        'role_id': role['RoleId'],
                        'arn': role['Arn'],
                        'create_date': role['CreateDate'].isoformat(),
                        'assume_role_policy': role.get('AssumeRolePolicyDocument'),
                        'max_session_duration': role.get('MaxSessionDuration', 3600),
                        'attached_policies': [],
                        'inline_policies': []
                    }
                    try:
                        pols = iam_client.list_attached_role_policies(RoleName=role['RoleName'])
                        for policy in pols['AttachedPolicies']:
                            r['attached_policies'].append({
                                'policy_name': policy['PolicyName'],
                                'policy_arn': policy['PolicyArn']
                            })
                    except:
                        pass
                    try:
                        inlines = iam_client.list_role_policies(RoleName=role['RoleName'])
                        r['inline_policies'] = inlines['PolicyNames']
                    except:
                        pass
                    iam_data['roles'].append(r)
            # 自定义策略
            try:
                policies_paginator = iam_client.get_paginator('list_policies')
                for page in policies_paginator.paginate(Scope='Local'):
                    for policy in page['Policies']:
                        iam_data['policies'].append({
                            'policy_name': policy['PolicyName'],
                            'policy_id': policy['PolicyId'],
                            'arn': policy['Arn'],
                            'create_date': policy['CreateDate'].isoformat(),
                            'update_date': policy['UpdateDate'].isoformat(),
                            'attachment_count': policy.get('AttachmentCount', 0),
                            'permissions_boundary_usage_count': policy.get('PermissionsBoundaryUsageCount', 0)
                        })
            except:
                pass
            print(f"   📊 IAM汇总: {len(iam_data['users'])}用户, {len(iam_data['roles'])}角色, {len(iam_data['policies'])}自定义策略")
        except Exception as e:
            print(f"   ❌ IAM枚举失败: {e}")
        self.audit_data['resources']['iam'] = iam_data

    def _enumerate_database_resources(self):
        """RDS与DynamoDB详细枚举"""
        print("\n🗄️ 数据库资源详细枚举...")
        db_data = {'rds_instances': [], 'rds_clusters': [], 'dynamodb_tables': []}
        for region in self.regions:
            print(f"   🌍 区域: {region}")
            try:
                rds_client = self.get_client('rds', region)
                # RDS实例
                instances_paginator = rds_client.get_paginator('describe_db_instances')
                for page in instances_paginator.paginate():
                    for ins in page['DBInstances']:
                        db_data['rds_instances'].append({
                            'db_instance_identifier': ins['DBInstanceIdentifier'],
                            'db_instance_class': ins['DBInstanceClass'],
                            'engine': ins['Engine'],
                            'engine_version': ins['EngineVersion'],
                            'master_username': ins['MasterUsername'],
                            'db_name': ins.get('DBName', ''),
                            'endpoint': ins.get('Endpoint', {}).get('Address', ''),
                            'port': ins.get('Endpoint', {}).get('Port', ''),
                            'allocated_storage': ins.get('AllocatedStorage', 0),
                            'storage_type': ins.get('StorageType', ''),
                            'multi_az': ins.get('MultiAZ', False),
                            'publicly_accessible': ins.get('PubliclyAccessible', False),
                            'vpc_security_groups': [sg['VpcSecurityGroupId'] for sg in ins.get('VpcSecurityGroups', [])],
                            'backup_retention_period': ins.get('BackupRetentionPeriod', 0),
                            'status': ins['DBInstanceStatus'],
                            'region': region
                        })
                # RDS集群
                try:
                    clusters_paginator = rds_client.get_paginator('describe_db_clusters')
                    for page in clusters_paginator.paginate():
                        for c in page['DBClusters']:
                            db_data['rds_clusters'].append({
                                'db_cluster_identifier': c['DBClusterIdentifier'],
                                'engine': c['Engine'],
                                'engine_version': c['EngineVersion'],
                                'master_username': c['MasterUsername'],
                                'database_name': c.get('DatabaseName', ''),
                                'endpoint': c.get('Endpoint', ''),
                                'reader_endpoint': c.get('ReaderEndpoint', ''),
                                'port': c.get('Port', ''),
                                'status': c['Status'],
                                'multi_az': c.get('MultiAZ', False),
                                'vpc_security_groups': [sg['VpcSecurityGroupId'] for sg in c.get('VpcSecurityGroups', [])],
                                'backup_retention_period': c.get('BackupRetentionPeriod', 0),
                                'region': region
                            })
                except:
                    pass
                # DynamoDB
                dyn = self.get_client('dynamodb', region)
                try:
                    tables = dyn.list_tables()
                    for name in tables.get('TableNames', []):
                        try:
                            desc = dyn.describe_table(TableName=name).get('Table', {})
                            db_data['dynamodb_tables'].append({
                                'table_name': name,
                                'table_status': desc.get('TableStatus', 'N/A'),
                                'item_count': desc.get('ItemCount', 0),
                                'table_size_bytes': desc.get('TableSizeBytes', 0),
                                'creation_date': desc.get('CreationDateTime', '').isoformat() if desc.get('CreationDateTime') else '',
                                'billing_mode': desc.get('BillingModeSummary', {}).get('BillingMode', 'Unknown'),
                                'region': region
                            })
                        except:
                            pass
                except:
                    pass
                print(f"      RDS实例: {len([x for x in db_data['rds_instances'] if x['region']==region])} | "
                      f"RDS集群: {len([x for x in db_data['rds_clusters'] if x['region']==region])} | "
                      f"DynamoDB: {len([x for x in db_data['dynamodb_tables'] if x['region']==region])}")
            except Exception as e:
                print(f"      ❌ 区域 {region} 数据库枚举失败: {e}")
        total = len(db_data['rds_instances']) + len(db_data['rds_clusters']) + len(db_data['dynamodb_tables'])
        print(f"   📊 数据库汇总: {total}项")
        self.audit_data['resources']['databases'] = db_data

    def _enumerate_lambda_resources(self):
        """Lambda函数枚举（仅收集环境变量键名）"""
        print("\n⚡ Lambda函数详细枚举...")
        lambda_data = {'functions': []}
        for region in self.regions:
            print(f"   🌍 区域: {region}")
            try:
                client = self.get_client('lambda', region)
                paginator = client.get_paginator('list_functions')
                region_functions = []
                for page in paginator.paginate():
                    for fn in page['Functions']:
                        info = {
                            'function_name': fn['FunctionName'],
                            'function_arn': fn['FunctionArn'],
                            'runtime': fn.get('Runtime', ''),
                            'role': fn.get('Role', ''),
                            'handler': fn.get('Handler', ''),
                            'code_size': fn.get('CodeSize', 0),
                            'description': fn.get('Description', ''),
                            'timeout': fn.get('Timeout', 0),
                            'memory_size': fn.get('MemorySize', 0),
                            'last_modified': fn.get('LastModified', ''),
                            'environment_variables': [],
                            'region': region
                        }
                        if 'Environment' in fn and 'Variables' in fn['Environment']:
                            info['environment_variables'] = list(fn['Environment']['Variables'].keys())
                        region_functions.append(info)
                lambda_data['functions'].extend(region_functions)
                print(f"      Lambda函数: {len(region_functions)}")
            except Exception as e:
                print(f"      ❌ 区域 {region} Lambda枚举失败: {e}")
        print(f"   📊 Lambda汇总: {len(lambda_data['functions'])}个函数")
        self.audit_data['resources']['lambda'] = lambda_data

    def _enumerate_network_resources(self):
        """网络资源：路由表、IGW(互联网网关)、NAT GW(网络地址转换网关)、VPC端点、子网"""
        print("\n🌐 网络资源详细枚举...")
        network_data = {'route_tables': [], 'internet_gateways': [], 'nat_gateways': [], 'vpc_endpoints': [], 'subnets': []}
        for region in self.regions:
            print(f"   🌍 区域: {region}")
            try:
                ec2 = self.get_client('ec2', region)
                # 路由表
                rts = ec2.describe_route_tables()
                for rt in rts['RouteTables']:
                    item = {
                        'route_table_id': rt['RouteTableId'],
                        'vpc_id': rt.get('VpcId', ''),
                        'routes': [],
                        'associations': [],
                        'region': region
                    }
                    for r in rt['Routes']:
                        item['routes'].append({
                            'destination': r.get('DestinationCidrBlock', r.get('DestinationPrefixListId', '')),
                            'target': self._get_route_target(r),
                            'state': r.get('State', 'active')
                        })
                    for a in rt.get('Associations', []):
                        item['associations'].append({'subnet_id': a.get('SubnetId', ''), 'main': a.get('Main', False)})
                    network_data['route_tables'].append(item)
                # IGW
                igws = ec2.describe_internet_gateways()
                for igw in igws['InternetGateways']:
                    network_data['internet_gateways'].append({
                        'internet_gateway_id': igw['InternetGatewayId'],
                        'attachments': [att['VpcId'] for att in igw.get('Attachments', [])],
                        'region': region
                    })
                # NAT GW
                try:
                    ngws = ec2.describe_nat_gateways()
                    for n in ngws.get('NatGateways', []):
                        network_data['nat_gateways'].append({
                            'nat_gateway_id': n['NatGatewayId'],
                            'state': n['State'],
                            'subnet_id': n['SubnetId'],
                            'vpc_id': n['VpcId'],
                            'public_ips': [addr.get('PublicIp') for addr in n.get('NatGatewayAddresses', []) if addr.get('PublicIp')],
                            'region': region
                        })
                except:
                    pass
                # VPC端点
                try:
                    eps = ec2.describe_vpc_endpoints()
                    for ep in eps.get('VpcEndpoints', []):
                        network_data['vpc_endpoints'].append({
                            'vpc_endpoint_id': ep['VpcEndpointId'],
                            'service_name': ep['ServiceName'],
                            'vpc_id': ep['VpcId'],
                            'endpoint_type': ep['VpcEndpointType'],
                            'state': ep['State'],
                            'region': region
                        })
                except:
                    pass
                # 子网
                subs = ec2.describe_subnets()
                for sn in subs['Subnets']:
                    network_data['subnets'].append({
                        'subnet_id': sn['SubnetId'],
                        'vpc_id': sn.get('VpcId', ''),
                        'cidr_block': sn['CidrBlock'],
                        'availability_zone': sn['AvailabilityZone'],
                        'available_ip_address_count': sn['AvailableIpAddressCount'],
                        'map_public_ip_on_launch': sn.get('MapPublicIpOnLaunch', False),
                        'region': region
                    })
                print(f"      路由表: {len([x for x in network_data['route_tables'] if x['region']==region])} | "
                      f"IGW: {len([x for x in network_data['internet_gateways'] if x['region']==region])} | "
                      f"子网: {len([x for x in network_data['subnets'] if x['region']==region])}")
            except Exception as e:
                print(f"      ❌ 区域 {region} 网络资源枚举失败: {e}")
        self.audit_data['resources']['network'] = network_data

    def _enumerate_security_resources(self):
        """安全相关：Secrets、SSM参数、CloudTrail状态"""
        print("\n🔐 安全资源详细枚举...")
        security_data = {'secrets': [], 'parameters': [], 'cloudtrail_trails': []}
        for region in self.regions:
            print(f"   🌍 区域: {region}")
            try:
                # Secrets
                sec = self.get_client('secretsmanager', region)
                try:
                    paginator = sec.get_paginator('list_secrets')
                    for page in paginator.paginate():
                        for s in page['SecretList']:
                            security_data['secrets'].append({
                                'name': s['Name'],
                                'arn': s['ARN'],
                                'description': s.get('Description', ''),
                                'created_date': s.get('CreatedDate', '').isoformat() if s.get('CreatedDate') else '',
                                'last_changed_date': s.get('LastChangedDate', '').isoformat() if s.get('LastChangedDate') else '',
                                'region': region
                            })
                except:
                    pass
                # SSM 参数
                ssm = self.get_client('ssm', region)
                try:
                    paginator = ssm.get_paginator('describe_parameters')
                    for page in paginator.paginate():
                        for p in page['Parameters']:
                            security_data['parameters'].append({
                                'name': p['Name'],
                                'type': p['Type'],
                                'description': p.get('Description', ''),
                                'last_modified_date': p.get('LastModifiedDate', '').isoformat() if p.get('LastModifiedDate') else '',
                                'region': region
                            })
                except:
                    pass
                # CloudTrail
                ct = self.get_client('cloudtrail', region)
                try:
                    trails = ct.describe_trails()
                    for t in trails.get('trailList', []):
                        item = {
                            'name': t['Name'],
                            'arn': t.get('TrailARN', ''),
                            's3_bucket_name': t.get('S3BucketName', ''),
                            'include_global_service_events': t.get('IncludeGlobalServiceEvents', False),
                            'is_multi_region_trail': t.get('IsMultiRegionTrail', False),
                            'is_logging': False,
                            'region': region
                        }
                        try:
                            status = ct.get_trail_status(Name=t['Name'])
                            item['is_logging'] = status.get('IsLogging', False)
                        except:
                            pass
                        security_data['cloudtrail_trails'].append(item)
                except:
                    pass
                print(f"      Secrets: {len([x for x in security_data['secrets'] if x['region']==region])} | "
                      f"SSM参数: {len([x for x in security_data['parameters'] if x['region']==region])} | "
                      f"CloudTrail: {len([x for x in security_data['cloudtrail_trails'] if x['region']==region])}")
            except Exception as e:
                print(f"      ❌ 区域 {region} 安全资源枚举失败: {e}")
        self.audit_data['resources']['security'] = security_data

    def _enumerate_organization_resources(self):
        """Organizations组织枚举（组织、账户、根与OU）"""
        print("\n🏢 Organizations组织信息枚举...")
        org_data = {'organization': {}, 'accounts': [], 'organizational_units': []}
        try:
            org = self.get_client('organizations', region='us-east-1')  # organizations是全局服务
            # 组织详情
            try:
                org_desc = org.describe_organization()
                org_info = org_desc['Organization']
                org_data['organization'] = {
                    'id': org_info['Id'],
                    'master_account_id': org_info.get('MasterAccountId'),
                    'master_account_email': org_info.get('MasterAccountEmail'),
                    'feature_set': org_info.get('FeatureSet'),
                    'available_policy_types': [pt['Type'] for pt in org_info.get('AvailablePolicyTypes', [])]
                }
                print(f"   组织ID: {org_data['organization']['id']} | 主账户: {org_data['organization']['master_account_email']}")
            except ClientError as e:
                print(f"   ❌ 获取组织信息失败: {e}")
            # 账户列表
            try:
                paginator = org.get_paginator('list_accounts')
                for page in paginator.paginate():
                    for acc in page['Accounts']:
                        org_data['accounts'].append({
                            'id': acc['Id'],
                            'name': acc['Name'],
                            'email': acc['Email'],
                            'status': acc['Status'],
                            'joined_method': acc['JoinedMethod'],
                            'joined_timestamp': acc.get('JoinedTimestamp', '').isoformat() if acc.get('JoinedTimestamp') else ''
                        })
                print(f"   账户数量: {len(org_data['accounts'])}")
            except ClientError as e:
                print(f"   ❌ 获取账户列表失败: {e}")
            # OU（按根枚举第一层）
            try:
                roots = org.list_roots()
                for root in roots['Roots']:
                    paginator = org.get_paginator('list_organizational_units_for_parent')
                    for page in paginator.paginate(ParentId=root['Id']):
                        for ou in page['OrganizationalUnits']:
                            org_data['organizational_units'].append({
                                'id': ou['Id'],
                                'name': ou['Name'],
                                'arn': ou['Arn']
                            })
                print(f"   OU数量: {len(org_data['organizational_units'])}")
            except ClientError as e:
                print(f"   ❌ 获取组织单元失败: {e}")
        except Exception as e:
            print(f"   ❌ Organizations枚举失败: {e}")
        self.audit_data['resources']['organization'] = org_data

    # ========= 安全分析 =========
    def analyze_security_risks(self):
        """聚合安全风险分析"""
        print("\n" + "=" * 80)
        print("🚨 安全风险分析")
        print("=" * 80)
        risks = {'critical': [], 'high': [], 'medium': [], 'low': [], 'info': []}
        self._analyze_s3_risks(risks)
        self._analyze_ec2_risks(risks)
        self._analyze_iam_risks(risks)
        self._analyze_network_risks(risks)
        self._analyze_database_risks(risks)
        # 组织信息可见性（信息→高）
        org = self.audit_data['resources'].get('organization', {})
        if org.get('organization') or org.get('accounts'):
            risks['high'].append({
                'type': 'ORGANIZATION_ENUMERATION_ALLOWED',
                'resource': org.get('organization', {}).get('id', 'ORG'),
                'description': '具备Organizations组织/账户可见性，泄露组织结构元数据',
                'recommendation': '限制对organizations:*的访问，仅授予审计角色'
            })
        self.audit_data['security_analysis'] = risks
        print(f"\n🔥 严重: {len(risks['critical'])} | 🚨 高: {len(risks['high'])} | ⚠️ 中: {len(risks['medium'])} | ℹ️ 低: {len(risks['low'])}")

    def _analyze_s3_risks(self, risks):
        s3 = self.audit_data['resources'].get('s3', {})
        for b in s3.get('buckets', []):
            name = b['name']
            sec = b['security_config']
            if sec.get('encryption') == 'Disabled':
                risks['high'].append({
                    'type': 'S3_UNENCRYPTED_BUCKET',
                    'resource': name,
                    'description': f'S3存储桶 {name} 未启用加密',
                    'recommendation': '启用S3默认加密保护静态数据'
                })
            if not sec.get('public_access_blocked', True):
                risks['critical'].append({
                    'type': 'S3_PUBLIC_ACCESS_ALLOWED',
                    'resource': name,
                    'description': f'S3存储桶 {name} 允许公共访问',
                    'recommendation': '开启账户与桶级Public Access Block'
                })
            if sec.get('versioning') == 'Disabled':
                risks['medium'].append({
                    'type': 'S3_VERSIONING_DISABLED',
                    'resource': name,
                    'description': f'S3存储桶 {name} 未启用版本控制',
                    'recommendation': '开启版本控制以抵御误删与勒索'
                })

    def _analyze_ec2_risks(self, risks):
        ec2 = self.audit_data['resources'].get('ec2', {})
        for sg in ec2.get('security_groups', []):
            rid = f"{sg['group_name']} ({sg['group_id']})"
            for rule in sg['inbound_rules']:
                for cidr in rule['ip_ranges']:
                    if cidr == '0.0.0.0/0':
                        fp = rule.get('from_port', 'All')
                        dangerous = [22, 3389, 1433, 3306, 5432]
                        if fp == 'All' or fp in dangerous:
                            risks['critical'].append({
                                'type': 'SECURITY_GROUP_DANGEROUS_INBOUND',
                                'resource': rid,
                                'description': f'对全网开放危险端口 {fp}',
                                'recommendation': '限制源IP；SSH/RDP仅允许运维出口IP；优先用SSM Session Manager'
                            })
                        elif fp not in [80, 443]:
                            risks['high'].append({
                                'type': 'SECURITY_GROUP_OPEN_INBOUND',
                                'resource': rid,
                                'description': f'对全网开放端口 {fp}',
                                'recommendation': '按需最小化规则并收敛来源网段'
                            })
        for ins in ec2.get('instances', []):
            if ins.get('public_ip'):
                risks['medium'].append({
                    'type': 'EC2_PUBLIC_IP_ASSIGNED',
                    'resource': ins['instance_id'],
                    'description': f'实例 {ins["instance_id"]} 带公网IP',
                    'recommendation': '评估必要性；优先走NAT/代理出网'
                })
            if not ins.get('key_name'):
                risks['low'].append({
                    'type': 'EC2_NO_KEY_PAIR',
                    'resource': ins['instance_id'],
                    'description': f'实例 {ins["instance_id"]} 未关联SSH密钥对',
                    'recommendation': '为实例绑定密钥或使用SSM登录'
                })

    def _analyze_iam_risks(self, risks):
        iam = self.audit_data['resources'].get('iam', {})
        for user in iam.get('users', []):
            u = user['username']
            if len(user.get('access_keys', [])) > 1:
                risks['medium'].append({
                    'type': 'IAM_MULTIPLE_ACCESS_KEYS',
                    'resource': u,
                    'description': f'IAM用户 {u} 拥有多个访问密钥',
                    'recommendation': '保留单key并启强制轮换'
                })
            if user.get('password_last_used') == 'Never':
                risks['low'].append({
                    'type': 'IAM_UNUSED_USER',
                    'resource': u,
                    'description': f'IAM用户 {u} 从未使用密码登录',
                    'recommendation': '清理未使用账号'
                })
            if len(user.get('attached_policies', [])) > 10:
                risks['medium'].append({
                    'type': 'IAM_EXCESSIVE_POLICIES',
                    'resource': u,
                    'description': f'IAM用户 {u} 附加策略过多',
                    'recommendation': '聚合策略并按职责最小授权'
                })
        for role in iam.get('roles', []):
            pol = role.get('assume_role_policy')
            if isinstance(pol, dict):
                for st in pol.get('Statement', []):
                    if st.get('Effect') == 'Allow':
                        pr = st.get('Principal', {})
                        if pr == '*' or pr.get('AWS') == '*':
                            risks['critical'].append({
                                'type': 'IAM_ROLE_TRUST_WILDCARD',
                                'resource': role['role_name'],
                                'description': f'角色 {role["role_name"]} 信任策略包含通配符主体',
                                'recommendation': '将信任主体限定为具体账户/服务/条件'
                            })

    def _analyze_network_risks(self, risks):
        network = self.audit_data['resources'].get('network', {})
        ec2 = self.audit_data['resources'].get('ec2', {})
        defaults = [v for v in ec2.get('vpcs', []) if v.get('is_default', False)]
        if defaults:
            risks['high'].append({
                'type': 'NETWORK_DEFAULT_VPC_IN_USE',
                'resource': ', '.join([v['vpc_id'] for v in defaults]),
                'description': '使用默认VPC',
                'recommendation': '迁移至自定义VPC并删除默认VPC'
            })
        for rt in network.get('route_tables', []):
            for r in rt['routes']:
                if r['destination'] == '0.0.0.0/0' and str(r['target']).startswith('igw-'):
                    for a in rt['associations']:
                        if a.get('main', False):
                            risks['high'].append({
                                'type': 'NETWORK_MAIN_ROUTE_TABLE_IGW',
                                'resource': rt['route_table_id'],
                                'description': '主路由表直连IGW(互联网网关)',
                                'recommendation': '将上网路由放到自定义子网路由表'
                            })
                            break

    def _analyze_database_risks(self, risks):
        db = self.audit_data['resources'].get('databases', {})
        for ins in db.get('rds_instances', []):
            rid = ins['db_instance_identifier']
            if ins.get('publicly_accessible', False):
                risks['critical'].append({
                    'type': 'DATABASE_PUBLICLY_ACCESSIBLE',
                    'resource': rid,
                    'description': f'RDS实例 {rid} 允许公共访问',
                    'recommendation': '禁用Public，置于私有子网经内网访问'
                })
            if ins.get('backup_retention_period', 0) == 0:
                risks['high'].append({
                    'type': 'DATABASE_NO_BACKUP',
                    'resource': rid,
                    'description': f'RDS实例 {rid} 未配置备份',
                    'recommendation': '启用自动备份并测试恢复流程'
                })
            if not ins.get('multi_az', False):
                risks['medium'].append({
                    'type': 'DATABASE_SINGLE_AZ',
                    'resource': rid,
                    'description': f'RDS实例 {rid} 未启用多AZ',
                    'recommendation': '开启多AZ以提高可用性'
                })

    # ========= 危险权限测试（写操作） =========
    def test_dangerous_permissions(self):
        """
        仅在二次强确认后执行：尝试 create_user / create_role 并清理。
        ⚠️ 可能产生费用或审计记录，请确保授权。
        """
        print("\n" + "=" * 80)
        print("⚠️ 危险权限测试（写操作）")
        print("=" * 80)
        print("此测试会创建临时IAM用户与角色用于验证写权限，随后尝试清理。")
        confirm = input("请输入 'I_UNDERSTAND' 以继续，其他任意键取消：").strip()
        results = {}
        if confirm != 'I_UNDERSTAND':
            print("已跳过危险权限测试。")
            self.audit_data['dangerous_tests'] = results
            return results

        iam = self.get_client('iam')
        suffix = str(int(time.time()))
        tests = [
            {
                'action': 'create_user',
                'params': {'UserName': f'test-user-{suffix}'},
                'cleanup': ('delete_user', {'UserName': f'test-user-{suffix}'}),
                'desc': '创建IAM用户'
            },
            {
                'action': 'create_role',
                'params': {
                    'RoleName': f'test-role-{suffix}',
                    'AssumeRolePolicyDocument': json.dumps({
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "ec2.amazonaws.com"},
                            "Action": "sts:AssumeRole"
                        }]
                    })
                },
                'cleanup': ('delete_role', {'RoleName': f'test-role-{suffix}'}),
                'desc': '创建IAM角色'
            }
        ]
        for t in tests:
            try:
                print(f"🧪 {t['desc']} ({t['action']}) ...")
                getattr(iam, t['action'])(**t['params'])
                results[t['action']] = "SUCCESS"
                print(f"   🚨 成功执行危险操作: {t['action']}")
                # 清理
                try:
                    time.sleep(2)
                    getattr(iam, t['cleanup'][0])(**t['cleanup'][1])
                    print("   🧹 已清理测试资源")
                except Exception as ce:
                    print(f"   ⚠️ 清理失败: {ce}")
            except ClientError as e:
                code = e.response['Error']['Code']
                print(f"   ✅ 危险操作被阻止: {code}")
                results[t['action']] = code
            except Exception as e:
                print(f"   ❌ 测试错误: {e}")
                results[t['action']] = str(e)

        self.audit_data['dangerous_tests'] = results
        return results

    # ========= 报告生成 =========
    def generate_comprehensive_report(self):
        """生成JSON/CSV/HTML与风险评估"""
        print("\n" + "=" * 80)
        print("📊 生成综合审计报告")
        print("=" * 80)
        self._generate_json_report()
        self._generate_csv_reports()
        self._generate_html_report()
        self._generate_risk_assessment()

    def _generate_json_report(self):
        """保存整包JSON"""
        print("💾 生成JSON报告...")
        path = os.path.join(self.report_dir, 'comprehensive_audit_report.json')
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(self.audit_data, f, ensure_ascii=False, indent=2, default=str)
        print("   ✅ JSON报告已保存: comprehensive_audit_report.json")

    def _generate_csv_reports(self):
        """CSV导出：S3、EC2、IAM用户、Organizations账户、风险、网络等"""
        print("📄 生成CSV报告...")
        # S3
        s3 = self.audit_data['resources'].get('s3', {})
        if s3.get('buckets'):
            file = os.path.join(self.report_dir, 'S3_buckets_report.csv')
            with open(file, 'w', newline='', encoding='utf-8') as f:
                fields = ['name', 'region', 'creation_date', 'object_count', 'total_size', 'encryption', 'public_access_blocked', 'versioning']
                w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
                for b in s3['buckets']:
                    w.writerow({
                        'name': b['name'],
                        'region': b['region'],
                        'creation_date': b['creation_date'],
                        'object_count': b['object_count'],
                        'total_size': b['total_size'],
                        'encryption': b['security_config'].get('encryption', 'Unknown'),
                        'public_access_blocked': b['security_config'].get('public_access_blocked', False),
                        'versioning': b['security_config'].get('versioning', 'Unknown')
                    })

        # EC2 —— 实例
        ec2 = self.audit_data['resources'].get('ec2', {})
        if ec2.get('instances'):
            file = os.path.join(self.report_dir, 'EC2_instances_report.csv')
            with open(file, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['instance_id', 'instance_type', 'state', 'region', 'private_ip', 'public_ip', 'vpc_id', 'key_name']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for instance in ec2.get('instances', []):
                    writer.writerow({
                        'instance_id': instance.get('instance_id', ''),
                        'instance_type': instance.get('instance_type', ''),
                        'state': instance.get('state', ''),
                        'region': instance.get('region', ''),
                        'private_ip': instance.get('private_ip', ''),
                        'public_ip': instance.get('public_ip', ''),
                        'vpc_id': instance.get('vpc_id', ''),
                        'key_name': instance.get('key_name', '')
                    })

        # EC2 —— 安全组
        if ec2.get('security_groups'):
            sg_csv = os.path.join(self.report_dir, 'EC2_security_groups_report.csv')
            with open(sg_csv, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['group_id', 'group_name', 'description', 'vpc_id', 'region', 'inbound_rules', 'outbound_rules']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for sg in ec2.get('security_groups', []):
                    writer.writerow({
                        'group_id': sg.get('group_id', ''),
                        'group_name': sg.get('group_name', ''),
                        'description': sg.get('description', ''),
                        'vpc_id': sg.get('vpc_id', ''),
                        'region': sg.get('region', ''),
                        'inbound_rules': json.dumps(sg.get('inbound_rules', []), ensure_ascii=False),
                        'outbound_rules': json.dumps(sg.get('outbound_rules', []), ensure_ascii=False)
                    })

        # EC2 —— VPC
        if ec2.get('vpcs'):
            vpc_csv = os.path.join(self.report_dir, 'EC2_vpcs_report.csv')
            with open(vpc_csv, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['vpc_id', 'state', 'cidr_block', 'is_default', 'region', 'tags']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for vpc in ec2.get('vpcs', []):
                    writer.writerow({
                        'vpc_id': vpc.get('vpc_id', ''),
                        'state': vpc.get('state', ''),
                        'cidr_block': vpc.get('cidr_block', ''),
                        'is_default': vpc.get('is_default', False),
                        'region': vpc.get('region', ''),
                        'tags': json.dumps(vpc.get('tags', {}), ensure_ascii=False)
                    })

        # EC2 —— 密钥对
        if ec2.get('key_pairs'):
            kp_csv = os.path.join(self.report_dir, 'EC2_key_pairs_report.csv')
            with open(kp_csv, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['key_name', 'key_fingerprint', 'key_type', 'region']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for kp in ec2.get('key_pairs', []):
                    writer.writerow({
                        'key_name': kp.get('key_name', ''),
                        'key_fingerprint': kp.get('key_fingerprint', ''),
                        'key_type': kp.get('key_type', ''),
                        'region': kp.get('region', '')
                    })

        # IAM 用户
        iam_data = self.audit_data.get('resources', {}).get('iam', {})
        if iam_data.get('users'):
            iam_users_csv = os.path.join(self.report_dir, 'IAM_users_report.csv')
            with open(iam_users_csv, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['username', 'user_id', 'arn', 'create_date', 'password_last_used', 'access_keys', 'attached_policies', 'inline_policies', 'groups']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for user in iam_data['users']:
                    writer.writerow({
                        'username': user.get('username', ''),
                        'user_id': user.get('user_id', ''),
                        'arn': user.get('arn', ''),
                        'create_date': user.get('create_date', ''),
                        'password_last_used': user.get('password_last_used', ''),
                        'access_keys': json.dumps(user.get('access_keys', []), ensure_ascii=False),
                        'attached_policies': json.dumps(user.get('attached_policies', []), ensure_ascii=False),
                        'inline_policies': json.dumps(user.get('inline_policies', []), ensure_ascii=False),
                        'groups': json.dumps(user.get('groups', []), ensure_ascii=False)
                    })

        # IAM 角色
        if iam_data.get('roles'):
            iam_roles_csv = os.path.join(self.report_dir, 'IAM_roles_report.csv')
            with open(iam_roles_csv, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['role_name', 'role_id', 'arn', 'create_date', 'assume_role_policy', 'max_session_duration', 'attached_policies', 'inline_policies']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for role in iam_data['roles']:
                    writer.writerow({
                        'role_name': role.get('role_name', ''),
                        'role_id': role.get('role_id', ''),
                        'arn': role.get('arn', ''),
                        'create_date': role.get('create_date', ''),
                        'assume_role_policy': json.dumps(role.get('assume_role_policy', {}), ensure_ascii=False),
                        'max_session_duration': role.get('max_session_duration', 3600),
                        'attached_policies': json.dumps(role.get('attached_policies', []), ensure_ascii=False),
                        'inline_policies': json.dumps(role.get('inline_policies', []), ensure_ascii=False)
                    })

        # IAM 自定义策略
        if iam_data.get('policies'):
            iam_policies_csv = os.path.join(self.report_dir, 'IAM_policies_report.csv')
            with open(iam_policies_csv, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['policy_name', 'policy_id', 'arn', 'create_date', 'update_date', 'attachment_count', 'permissions_boundary_usage_count']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for p in iam_data['policies']:
                    writer.writerow({
                        'policy_name': p.get('policy_name', ''),
                        'policy_id': p.get('policy_id', ''),
                        'arn': p.get('arn', ''),
                        'create_date': p.get('create_date', ''),
                        'update_date': p.get('update_date', ''),
                        'attachment_count': p.get('attachment_count', 0),
                        'permissions_boundary_usage_count': p.get('permissions_boundary_usage_count', 0)
                    })

        # 数据库资源
        db_data = self.audit_data.get('resources', {}).get('databases', {})
        if db_data.get('rds_instances'):
            rds_csv = os.path.join(self.report_dir, 'RDS_instances_report.csv')
            with open(rds_csv, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['db_instance_identifier', 'db_instance_class', 'engine', 'engine_version', 'master_username',
                              'db_name', 'endpoint', 'port', 'allocated_storage', 'storage_type', 'multi_az',
                              'publicly_accessible', 'vpc_security_groups', 'backup_retention_period', 'status', 'region']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for inst in db_data['rds_instances']:
                    writer.writerow({
                        'db_instance_identifier': inst.get('db_instance_identifier', ''),
                        'db_instance_class': inst.get('db_instance_class', ''),
                        'engine': inst.get('engine', ''),
                        'engine_version': inst.get('engine_version', ''),
                        'master_username': inst.get('master_username', ''),
                        'db_name': inst.get('db_name', ''),
                        'endpoint': inst.get('endpoint', ''),
                        'port': inst.get('port', ''),
                        'allocated_storage': inst.get('allocated_storage', 0),
                        'storage_type': inst.get('storage_type', ''),
                        'multi_az': inst.get('multi_az', False),
                        'publicly_accessible': inst.get('publicly_accessible', False),
                        'vpc_security_groups': json.dumps(inst.get('vpc_security_groups', []), ensure_ascii=False),
                        'backup_retention_period': inst.get('backup_retention_period', 0),
                        'status': inst.get('status', ''),
                        'region': inst.get('region', '')
                    })
        if db_data.get('rds_clusters'):
            rds_cluster_csv = os.path.join(self.report_dir, 'RDS_clusters_report.csv')
            with open(rds_cluster_csv, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['db_cluster_identifier', 'engine', 'engine_version', 'master_username', 'database_name',
                              'endpoint', 'reader_endpoint', 'port', 'status', 'multi_az', 'vpc_security_groups',
                              'backup_retention_period', 'region']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for cl in db_data['rds_clusters']:
                    writer.writerow({
                        'db_cluster_identifier': cl.get('db_cluster_identifier', ''),
                        'engine': cl.get('engine', ''),
                        'engine_version': cl.get('engine_version', ''),
                        'master_username': cl.get('master_username', ''),
                        'database_name': cl.get('database_name', ''),
                        'endpoint': cl.get('endpoint', ''),
                        'reader_endpoint': cl.get('reader_endpoint', ''),
                        'port': cl.get('port', ''),
                        'status': cl.get('status', ''),
                        'multi_az': cl.get('multi_az', False),
                        'vpc_security_groups': json.dumps(cl.get('vpc_security_groups', []), ensure_ascii=False),
                        'backup_retention_period': cl.get('backup_retention_period', 0),
                        'region': cl.get('region', '')
                    })

        if db_data.get('dynamodb_tables'):
            dynamo_csv = os.path.join(self.report_dir, 'DynamoDB_tables_report.csv')
            with open(dynamo_csv, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['table_name', 'table_status', 'item_count', 'table_size_bytes', 'creation_date', 'billing_mode', 'region']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for t in db_data['dynamodb_tables']:
                    writer.writerow({
                        'table_name': t.get('table_name', ''),
                        'table_status': t.get('table_status', ''),
                        'item_count': t.get('item_count', 0),
                        'table_size_bytes': t.get('table_size_bytes', 0),
                        'creation_date': t.get('creation_date', ''),
                        'billing_mode': t.get('billing_mode', ''),
                        'region': t.get('region', '')
                    })

        # Lambda 函数
        lambda_data = self.audit_data.get('resources', {}).get('lambda', {})
        if lambda_data.get('functions'):
            lambda_csv = os.path.join(self.report_dir, 'Lambda_functions_report.csv')
            with open(lambda_csv, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['function_name', 'function_arn', 'runtime', 'role', 'handler', 'code_size',
                              'description', 'timeout', 'memory_size', 'last_modified', 'environment_variables', 'region']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for fn in lambda_data['functions']:
                    writer.writerow({
                        'function_name': fn.get('function_name', ''),
                        'function_arn': fn.get('function_arn', ''),
                        'runtime': fn.get('runtime', ''),
                        'role': fn.get('role', ''),
                        'handler': fn.get('handler', ''),
                        'code_size': fn.get('code_size', 0),
                        'description': fn.get('description', ''),
                        'timeout': fn.get('timeout', 0),
                        'memory_size': fn.get('memory_size', 0),
                        'last_modified': fn.get('last_modified', ''),
                        'environment_variables': json.dumps(fn.get('environment_variables', []), ensure_ascii=False),
                        'region': fn.get('region', '')
                    })

        # 网络清单（路由表 / IGW / NAT / 端点 / 子网）
        network = self.audit_data.get('resources', {}).get('network', {})
        if network.get('route_tables'):
            rt_csv = os.path.join(self.report_dir, 'Network_route_tables_report.csv')
            with open(rt_csv, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['route_table_id', 'vpc_id', 'region', 'routes', 'associations']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for rt in network['route_tables']:
                    writer.writerow({
                        'route_table_id': rt.get('route_table_id', ''),
                        'vpc_id': rt.get('vpc_id', ''),
                        'region': rt.get('region', ''),
                        'routes': json.dumps(rt.get('routes', []), ensure_ascii=False),
                        'associations': json.dumps(rt.get('associations', []), ensure_ascii=False)
                    })

        if network.get('internet_gateways'):
            igw_csv = os.path.join(self.report_dir, 'Network_internet_gateways_report.csv')
            with open(igw_csv, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['internet_gateway_id', 'attachments', 'region']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for igw in network['internet_gateways']:
                    writer.writerow({
                        'internet_gateway_id': igw.get('internet_gateway_id', ''),
                        'attachments': json.dumps(igw.get('attachments', []), ensure_ascii=False),
                        'region': igw.get('region', '')
                    })

        if network.get('nat_gateways'):
            nat_csv = os.path.join(self.report_dir, 'Network_nat_gateways_report.csv')
            with open(nat_csv, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['nat_gateway_id', 'state', 'subnet_id', 'vpc_id', 'public_ips', 'region']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for nat in network['nat_gateways']:
                    writer.writerow({
                        'nat_gateway_id': nat.get('nat_gateway_id', ''),
                        'state': nat.get('state', ''),
                        'subnet_id': nat.get('subnet_id', ''),
                        'vpc_id': nat.get('vpc_id', ''),
                        'public_ips': json.dumps(nat.get('public_ips', []), ensure_ascii=False),
                        'region': nat.get('region', '')
                    })

        if network.get('vpc_endpoints'):
            ep_csv = os.path.join(self.report_dir, 'Network_vpc_endpoints_report.csv')
            with open(ep_csv, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['vpc_endpoint_id', 'service_name', 'vpc_id', 'endpoint_type', 'state', 'region']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for ep in network['vpc_endpoints']:
                    writer.writerow({
                        'vpc_endpoint_id': ep.get('vpc_endpoint_id', ''),
                        'service_name': ep.get('service_name', ''),
                        'vpc_id': ep.get('vpc_id', ''),
                        'endpoint_type': ep.get('endpoint_type', ''),
                        'state': ep.get('state', ''),
                        'region': ep.get('region', '')
                    })

        if network.get('subnets'):
            subnet_csv = os.path.join(self.report_dir, 'Network_subnets_report.csv')
            with open(subnet_csv, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['subnet_id', 'vpc_id', 'cidr_block', 'availability_zone', 'available_ip_address_count', 'map_public_ip_on_launch', 'region']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for sn in network['subnets']:
                    writer.writerow({
                        'subnet_id': sn.get('subnet_id', ''),
                        'vpc_id': sn.get('vpc_id', ''),
                        'cidr_block': sn.get('cidr_block', ''),
                        'availability_zone': sn.get('availability_zone', ''),
                        'available_ip_address_count': sn.get('available_ip_address_count', 0),
                        'map_public_ip_on_launch': sn.get('map_public_ip_on_launch', False),
                        'region': sn.get('region', '')
                    })

        # Secrets / SSM / CloudTrail
        sec = self.audit_data.get('resources', {}).get('security', {})
        if sec.get('secrets'):
            secrets_csv = os.path.join(self.report_dir, 'Secrets_manager_report.csv')
            with open(secrets_csv, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['name', 'arn', 'description', 'created_date', 'last_changed_date', 'region']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for s in sec['secrets']:
                    writer.writerow({
                        'name': s.get('name', ''),
                        'arn': s.get('arn', ''),
                        'description': s.get('description', ''),
                        'created_date': s.get('created_date', ''),
                        'last_changed_date': s.get('last_changed_date', ''),
                        'region': s.get('region', '')
                    })

        if sec.get('parameters'):
            ssm_csv = os.path.join(self.report_dir, 'SSM_parameters_report.csv')
            with open(ssm_csv, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['name', 'type', 'description', 'last_modified_date', 'region']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for p in sec['parameters']:
                    writer.writerow({
                        'name': p.get('name', ''),
                        'type': p.get('type', ''),
                        'description': p.get('description', ''),
                        'last_modified_date': p.get('last_modified_date', ''),
                        'region': p.get('region', '')
                    })

        if sec.get('cloudtrail_trails'):
            trails_csv = os.path.join(self.report_dir, 'CloudTrail_trails_report.csv')
            with open(trails_csv, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['name', 'arn', 's3_bucket_name', 'include_global_service_events', 'is_multi_region_trail', 'is_logging', 'region']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for t in sec['cloudtrail_trails']:
                    writer.writerow({
                        'name': t.get('name', ''),
                        'arn': t.get('arn', ''),
                        's3_bucket_name': t.get('s3_bucket_name', ''),
                        'include_global_service_events': t.get('include_global_service_events', False),
                        'is_multi_region_trail': t.get('is_multi_region_trail', False),
                        'is_logging': t.get('is_logging', False),
                        'region': t.get('region', '')
                    })

        # Organizations 账户（来自权限测试详情，快捷导出）
        perm_details = self.audit_data.get('permission_details', {})
        org_key = 'organizations.list_accounts'
        if perm_details.get(org_key, {}).get('accounts'):
            org_csv = os.path.join(self.report_dir, 'Organizations_accounts_report.csv')
            with open(org_csv, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['id', 'name', 'email']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for acc in perm_details[org_key]['accounts']:
                    writer.writerow({
                        'id': acc.get('id', ''),
                        'name': acc.get('name', ''),
                        'email': acc.get('email', '')
                    })

        print("   ✅ CSV报告已生成")

    # ---------- HTML 报告与风险评估 ----------
    def _generate_html_report(self):
        """生成HTML综合报告"""
        print("🌐 生成HTML报告...")
        stats = self._calculate_statistics()

        html_content = f"""
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>AWS综合安全审计报告</title>
            <style>
                body {{ font-family: 'Microsoft YaHei', Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f7fa; }}
                .container {{ max-width: 1400px; margin: 0 auto; }}
                .header {{ background: linear-gradient(135deg, #232F3E 0%, #FF9900 100%); color: white; padding: 30px; border-radius: 12px; margin-bottom: 30px; text-align: center; }}
                .header h1 {{ margin: 0; font-size: 2.5em; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }}
                .header p {{ margin: 10px 0 0 0; opacity: 0.9; font-size: 1.1em; }}

                .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }}
                .summary-card {{ background: white; padding: 25px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); border-left: 5px solid #3498db; }}
                .summary-card h3 {{ margin: 0 0 15px 0; color: #2c3e50; font-size: 1.1em; }}
                .summary-card .number {{ font-size: 2.5em; font-weight: bold; color: #3498db; margin: 10px 0; }}

                .section {{ background: white; margin-bottom: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); overflow: hidden; }}
                .section-header {{ background: #34495e; color: white; padding: 20px; font-size: 1.4em; font-weight: bold; }}
                .section-content {{ padding: 25px; }}

                .risk-critical {{ border-left: 5px solid #e74c3c; }}
                .risk-high {{ border-left: 5px solid #f39c12; }}
                .risk-medium {{ border-left: 5px solid #f1c40f; }}
                .risk-low {{ border-left: 5px solid #27ae60; }}

                .risk-item {{ padding: 15px; margin: 10px 0; border-radius: 8px; border: 1px solid #ecf0f1; }}
                .risk-item h4 {{ margin: 0 0 10px 0; color: #2c3e50; }}
                .risk-item .resource {{ font-weight: bold; color: #8e44ad; margin: 5px 0; }}
                .risk-item .description {{ color: #34495e; margin: 10px 0; }}
                .risk-item .recommendation {{ background: #f8f9fa; padding: 10px; border-radius: 5px; margin: 10px 0; border-left: 3px solid #3498db; }}

                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ecf0f1; }}
                th {{ background: #f8f9fa; font-weight: bold; color: #2c3e50; }}
                tr:hover {{ background: #f8f9fa; }}

                .badge {{ display: inline-block; padding: 4px 8px; border-radius: 12px; font-size: 0.8em; font-weight: bold; margin: 2px; }}
                .badge-success {{ background: #d4edda; color: #155724; }}
                .badge-warning {{ background: #fff3cd; color: #856404; }}
                .badge-danger {{ background: #f8d7da; color: #721c24; }}
                .badge-info {{ background: #d1ecf1; color: #0c5460; }}

                .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }}
                .card {{ background: white; padding: 20px; border-radius: 8px; border: 1px solid #ecf0f1; }}

                .highlight {{ background: #fff5b3; padding: 2px 4px; border-radius: 4px; }}
                .code {{ font-family: 'Courier New', monospace; background: #f8f9fa; padding: 2px 4px; border-radius: 4px; }}

                @media (max-width: 768px) {{
                    .container {{ padding: 10px; }}
                    .summary {{ grid-template-columns: 1fr; }}
                    table {{ font-size: 0.9em; }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔍 AWS综合安全审计报告</h1>
                    <p>生成时间: {datetime.now().strftime('%Y年%m月%d日 %H:%M:%S')}</p>
                    <p>审计账户: {self.audit_data.get('identity', {}).get('arn', '未知')}</p>
                </div>
        """

        html_content += self._generate_summary_html(stats)
        html_content += self._generate_permissions_html()
        html_content += self._generate_risks_html()
        html_content += self._generate_resources_html()

        html_content += """
            </div>
        </body>
        </html>
        """

        html_file = os.path.join(self.report_dir, 'comprehensive_security_report.html')
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print("   ✅ HTML报告已保存: comprehensive_security_report.html")

    def _calculate_statistics(self):
        """计算统计数据"""
        stats = {}
        permissions = self.audit_data.get('permissions', {})
        stats['permissions_success'] = permissions.get('successful_count', 0)
        stats['permissions_total'] = permissions.get('total_tests', 0)
        stats['permissions_rate'] = permissions.get('success_rate', '0%')

        resources = self.audit_data.get('resources', {})
        stats['s3_buckets'] = len(resources.get('s3', {}).get('buckets', []))
        stats['ec2_instances'] = len(resources.get('ec2', {}).get('instances', []))
        stats['rds_instances'] = len(resources.get('databases', {}).get('rds_instances', []))
        stats['lambda_functions'] = len(resources.get('lambda', {}).get('functions', []))
        stats['iam_users'] = len(resources.get('iam', {}).get('users', []))
        stats['iam_roles'] = len(resources.get('iam', {}).get('roles', []))
        stats['vpcs'] = len(resources.get('ec2', {}).get('vpcs', []))
        stats['security_groups'] = len(resources.get('ec2', {}).get('security_groups', []))

        risks = self.audit_data.get('security_analysis', {})
        stats['critical_risks'] = len(risks.get('critical', []))
        stats['high_risks'] = len(risks.get('high', []))
        stats['medium_risks'] = len(risks.get('medium', []))
        stats['low_risks'] = len(risks.get('low', []))
        stats['total_risks'] = stats['critical_risks'] + stats['high_risks'] + stats['medium_risks'] + stats['low_risks']
        return stats

    def _generate_summary_html(self, stats):
        """生成概览HTML"""
        return f"""
        <div class="summary">
            <div class="summary-card">
                <h3>🔑 权限测试</h3>
                <div class="number">{stats['permissions_success']}/{stats['permissions_total']}</div>
                <p>成功率: {stats['permissions_rate']}</p>
            </div>
            <div class="summary-card">
                <h3>🚨 安全风险</h3>
                <div class="number">{stats['total_risks']}</div>
                <p>严重: {stats['critical_risks']} | 高: {stats['high_risks']} | 中: {stats['medium_risks']}</p>
            </div>
            <div class="summary-card">
                <h3>☁️ 计算资源</h3>
                <div class="number">{stats['ec2_instances']}</div>
                <p>EC2实例 | {stats['lambda_functions']} Lambda函数</p>
            </div>
            <div class="summary-card">
                <h3>💾 存储资源</h3>
                <div class="number">{stats['s3_buckets']}</div>
                <p>S3存储桶 | {stats['rds_instances']} RDS实例</p>
            </div>
            <div class="summary-card">
                <h3>🆔 身份管理</h3>
                <div class="number">{stats['iam_users']}</div>
                <p>IAM用户 | {stats['iam_roles']} IAM角色</p>
            </div>
            <div class="summary-card">
                <h3>🌐 网络资源</h3>
                <div class="number">{stats['vpcs']}</div>
                <p>VPC | {stats['security_groups']} 安全组</p>
            </div>
        </div>
        """

    def _generate_permissions_html(self):
        """生成权限分析HTML"""
        permissions = self.audit_data.get('permissions', {})
        results = permissions.get('results', {})

        html = """
        <div class="section">
            <div class="section-header">🔍 权限测试结果</div>
            <div class="section-content">
                <div class="grid">
        """

        successful_perms = [k for k, v in results.items() if v == "SUCCESS"]
        failed_perms = [k for k, v in results.items() if v != "SUCCESS"]

        html += f"""
                    <div class="card">
                        <h3 style="color: #27ae60;">✅ 可用权限 ({len(successful_perms)})</h3>
                        <ul>
        """
        for perm in successful_perms:
            html += f"<li>{perm}</li>"
        html += """
                        </ul>
                    </div>
                    <div class="card">
                        <h3 style="color: #e74c3c;">❌ 受限权限 ({len(failed_perms)})</h3>
                        <ul>
        """
        for perm in failed_perms[:20]:
            error = results[perm]
            html += f"<li>{perm} <span class='badge badge-danger'>{error}</span></li>"
        if len(failed_perms) > 20:
            html += f"<li>... 还有 {len(failed_perms) - 20} 个权限受限</li>"

        html += """
                        </ul>
                    </div>
                </div>
            </div>
        </div>
        """
        return html

    def _generate_risks_html(self):
        """生成风险分析HTML"""
        risks = self.audit_data.get('security_analysis', {})
        html = """
        <div class="section">
            <div class="section-header">🚨 安全风险分析</div>
            <div class="section-content">
        """
        for severity in ['critical', 'high', 'medium', 'low']:
            severity_risks = risks.get(severity, [])
            if not severity_risks:
                continue
            severity_names = {
                'critical': ('🔥 严重风险', 'risk-critical'),
                'high': ('🚨 高风险', 'risk-high'),
                'medium': ('⚠️ 中等风险', 'risk-medium'),
                'low': ('ℹ️ 低风险', 'risk-low')
            }
            name, css_class = severity_names[severity]
            html += f"<h3>{name} ({len(severity_risks)})</h3>"
            for risk in severity_risks:
                html += f"""
                    <div class="risk-item {css_class}">
                        <h4>{risk['type']}</h4>
                        <div class="resource">资源: {risk['resource']}</div>
                        <div class="description">{risk['description']}</div>
                        <div class="recommendation">
                            <strong>建议:</strong> {risk['recommendation']}
                        </div>
                    </div>
                """
        html += """
            </div>
        </div>
        """
        return html

    def _generate_resources_html(self):
        """生成资源清单HTML"""
        html = """
        <div class="section">
            <div class="section-header">📦 AWS资源清单</div>
            <div class="section-content">
        """
        # S3
        s3_data = self.audit_data['resources'].get('s3', {})
        if s3_data.get('buckets'):
            html += """
                <h3>🪣 S3存储桶</h3>
                <table>
                    <tr>
                        <th>存储桶名</th>
                        <th>区域</th>
                        <th>对象数量</th>
                        <th>总大小</th>
                        <th>加密状态</th>
                        <th>公共访问</th>
                    </tr>
            """
            for bucket in s3_data['buckets']:
                public_access = "已阻止" if bucket['security_config'].get('public_access_blocked') else "⚠️ 允许"
                encryption = bucket['security_config'].get('encryption', 'Unknown')
                html += f"""
                    <tr>
                        <td><span class="code">{bucket['name']}</span></td>
                        <td>{bucket['region']}</td>
                        <td>{bucket['object_count']:,}</td>
                        <td>{self._format_size(bucket['total_size'])}</td>
                        <td><span class="badge {'badge-success' if encryption == 'Enabled' else 'badge-warning'}">{encryption}</span></td>
                        <td><span class="badge {'badge-success' if '已阻止' in public_access else 'badge-danger'}">{public_access}</span></td>
                    </tr>
                """
            html += "</table>"

        # EC2
        ec2_data = self.audit_data['resources'].get('ec2', {})
        if ec2_data.get('instances'):
            html += """
                <h3>💻 EC2实例</h3>
                <table>
                    <tr>
                        <th>实例ID</th>
                        <th>类型</th>
                        <th>状态</th>
                        <th>区域</th>
                        <th>私有IP</th>
                        <th>公共IP</th>
                        <th>VPC</th>
                    </tr>
            """
            for instance in ec2_data['instances']:
                state_badge = {
                    'running': 'badge-success',
                    'stopped': 'badge-warning',
                    'terminated': 'badge-danger'
                }.get(instance['state'], 'badge-info')
                html += f"""
                    <tr>
                        <td><span class="code">{instance['instance_id']}</span></td>
                        <td>{instance['instance_type']}</td>
                        <td><span class="badge {state_badge}">{instance['state']}</span></td>
                        <td>{instance['region']}</td>
                        <td><span class="code">{instance['private_ip'] or 'N/A'}</span></td>
                        <td><span class="code {'highlight' if instance['public_ip'] else ''}">{instance['public_ip'] or 'N/A'}</span></td>
                        <td><span class="code">{instance['vpc_id'] or 'N/A'}</span></td>
                    </tr>
                """
            html += "</table>"

        # IAM用户（展示前20）
        iam_data = self.audit_data['resources'].get('iam', {})
        if iam_data.get('users'):
            html += """
                <h3>🆔 IAM用户</h3>
                <table>
                    <tr>
                        <th>用户名</th>
                        <th>创建时间</th>
                        <th>最后登录</th>
                        <th>访问密钥数</th>
                        <th>附加策略数</th>
                    </tr>
            """
            for user in iam_data['users'][:20]:
                last_used = user.get('password_last_used', 'Never')
                if last_used != 'Never':
                    last_used = last_used[:10]
                html += f"""
                    <tr>
                        <td><span class="code">{user['username']}</span></td>
                        <td>{user['create_date'][:10]}</td>
                        <td><span class="badge {'badge-warning' if last_used == 'Never' else 'badge-success'}">{last_used}</span></td>
                        <td>{len(user.get('access_keys', []))}</td>
                        <td>{len(user.get('attached_policies', []))}</td>
                    </tr>
                """
            if len(iam_data['users']) > 20:
                html += f"<tr><td colspan='5'>... 还有 {len(iam_data['users']) - 20} 个用户未显示</td></tr>"
            html += "</table>"

        # Organizations
        org = self.audit_data['resources'].get('organization', {})
        if org.get('organization') or org.get('accounts'):
            html += """
                <h3>🏢 Organizations</h3>
                <table>
                    <tr>
                        <th>账户ID</th>
                        <th>账户名</th>
                        <th>邮箱</th>
                        <th>状态</th>
                    </tr>
            """
            for acc in org.get('accounts', []):
                html += f"""
                    <tr>
                        <td>{acc.get('id','')}</td>
                        <td>{acc.get('name','')}</td>
                        <td>{acc.get('email','')}</td>
                        <td>{acc.get('status','')}</td>
                    </tr>
                """
            html += "</table>"

        html += """
            </div>
        </div>
        """
        return html

    def _generate_risk_assessment(self):
        """生成风险评估JSON并输出概览"""
        print("📋 生成风险评估报告...")
        risks = self.audit_data.get('security_analysis', {})
        stats = self._calculate_statistics()

        risk_score = (
            stats['critical_risks'] * 10 +
            stats['high_risks'] * 5 +
            stats['medium_risks'] * 2 +
            stats['low_risks'] * 1
        )
        if risk_score >= 50:
            risk_level = "🔥 极高风险 (CRITICAL)"
        elif risk_score >= 30:
            risk_level = "🚨 高风险 (HIGH)"
        elif risk_score >= 15:
            risk_level = "⚠️ 中等风险 (MEDIUM)"
        else:
            risk_level = "ℹ️ 低风险 (LOW)"

        assessment = {
            'overall_risk_level': risk_level,
            'risk_score': risk_score,
            'total_risks': stats['total_risks'],
            'critical_risks': stats['critical_risks'],
            'high_risks': stats['high_risks'],
            'medium_risks': stats['medium_risks'],
            'low_risks': stats['low_risks'],
            'recommendations': self._generate_recommendations(risks),
            'compliance_status': self._assess_compliance(),
            'next_steps': self._generate_next_steps()
        }

        assessment_file = os.path.join(self.report_dir, 'risk_assessment.json')
        with open(assessment_file, 'w', encoding='utf-8') as f:
            json.dump(assessment, f, ensure_ascii=False, indent=2, default=str)

        self.audit_data['risk_assessment'] = assessment
        print(f"   ✅ 风险评估已生成: risk_assessment.json")
        print(f"   🎯 总体风险等级: {risk_level}")
        print(f"   📊 风险评分: {risk_score}")

    def _generate_recommendations(self, risks):
        """生成修复建议"""
        recommendations = []
        risk_types = set()
        for severity_list in risks.values():
            for risk in severity_list:
                risk_types.add(risk['type'])

        if 'S3_PUBLIC_ACCESS_ALLOWED' in risk_types:
            recommendations.append({
                'priority': 'CRITICAL',
                'title': 'S3存储桶公共访问修复',
                'description': '立即禁用所有S3存储桶的公共访问，启用公共访问阻止设置',
                'action_items': [
                    '审查所有S3存储桶的公共访问配置',
                    '启用账户级别的S3公共访问阻止',
                    '对业务必需的公共访问使用CloudFront分发'
                ]
            })

        if 'SECURITY_GROUP_DANGEROUS_INBOUND' in risk_types:
            recommendations.append({
                'priority': 'CRITICAL',
                'title': '安全组规则修复',
                'description': '修复开放危险端口的安全组规则',
                'action_items': [
                    '审查所有对0.0.0.0/0开放的安全组规则',
                    '限制SSH(22)和RDP(3389)访问到特定IP',
                    '使用AWS Systems Manager Session Manager替代直接SSH访问'
                ]
            })

        if 'DATABASE_PUBLICLY_ACCESSIBLE' in risk_types:
            recommendations.append({
                'priority': 'HIGH',
                'title': '数据库安全加固',
                'description': '禁用数据库的公共访问',
                'action_items': [
                    '将所有RDS实例设置为非公共访问',
                    '确保数据库部署在私有子网',
                    '通过VPC内部或VPN访问数据库'
                ]
            })
        return recommendations

    def _assess_compliance(self):
        """评估合规性状态"""
        return {
            'frameworks': {
                'AWS_WELL_ARCHITECTED': self._assess_well_architected(),
                'CIS_BENCHMARKS': self._assess_cis_benchmarks(),
                'NIST_CYBERSECURITY': self._assess_nist()
            }
        }

    def _assess_well_architected(self):
        """评估AWS Well-Architected框架合规性"""
        score = 100
        issues = []
        risks = self.audit_data.get('security_analysis', {})
        if risks.get('critical') or risks.get('high'):
            score -= 30
            issues.append('存在严重或高风险安全问题')
        ec2_data = self.audit_data['resources'].get('ec2', {})
        default_vpcs = [vpc for vpc in ec2_data.get('vpcs', []) if vpc.get('is_default')]
        if default_vpcs:
            score -= 20
            issues.append('使用默认VPC影响可靠性')
        return {
            'score': max(0, score),
            'status': 'GOOD' if score >= 80 else 'NEEDS_IMPROVEMENT',
            'issues': issues
        }

    def _assess_cis_benchmarks(self):
        """评估CIS基准合规性"""
        score = 100
        issues = []
        # 可按需扩展更多具体的CIS控制检查
        return {
            'score': score,
            'status': 'PARTIAL' if score >= 60 else 'NON_COMPLIANT',
            'issues': issues
        }

    def _assess_nist(self):
        """评估NIST网络安全框架合规性"""
        score = 100
        issues = []
        # 可按需扩展识别/保护/检测/响应/恢复五大功能域的检查
        return {
            'score': score,
            'status': 'COMPLIANT' if score >= 70 else 'NON_COMPLIANT',
            'issues': issues
        }

    def _generate_next_steps(self):
        """生成后续步骤建议"""
        return [
            {'step': 1, 'title': '立即修复严重风险', 'description': '优先处理所有标记为严重的安全风险', 'timeline': '立即执行'},
            {'step': 2, 'title': '实施安全基线', 'description': '建立AWS安全配置基线，包括IAM策略、网络配置等', 'timeline': '1-2周内完成'},
            {'step': 3, 'title': '启用监控和告警', 'description': '配置CloudTrail、Config、GuardDuty等安全监控服务', 'timeline': '2-4周内完成'},
            {'step': 4, 'title': '定期安全审计', 'description': '建立定期的安全审计流程，推荐每月执行一次', 'timeline': '持续执行'}
        ]

    def _format_size(self, size_bytes):
        """格式化文件大小"""
        if not isinstance(size_bytes, (int, float)):
            return "0B"
        if size_bytes == 0:
            return "0B"
        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1
        return f"{size_bytes:.2f}{size_names[i]}"

    def _get_route_target(self, r):
        """从路由条目里提取目标ID，尽量给出人能看懂的标识"""
        keys = [
            'GatewayId', 'TransitGatewayId', 'NatGatewayId', 'NetworkInterfaceId',
            'VpcPeeringConnectionId', 'EgressOnlyInternetGatewayId', 'InstanceId',
            'CarrierGatewayId', 'LocalGatewayId'
        ]
        for k in keys:
            if r.get(k):
                return r[k]
        return r.get('Origin', 'unknown')

    def generate_final_summary(self):
        """生成最终总结（控制台输出）"""
        print("\n" + "=" * 100)
        print("🎯 AWS综合安全审计完成")
        print("=" * 100)
        stats = self._calculate_statistics()
        print(f"\n📊 审计统计:")
        print(f"   🔑 权限测试: {stats['permissions_success']}/{stats['permissions_total']} ({stats['permissions_rate']})")
        print(f"   📦 发现资源: S3({stats['s3_buckets']}) EC2({stats['ec2_instances']}) RDS({stats['rds_instances']}) Lambda({stats['lambda_functions']})")
        print(f"   🆔 身份管理: {stats['iam_users']}用户 {stats['iam_roles']}角色")
        print(f"   🌐 网络资源: {stats['vpcs']}个VPC {stats['security_groups']}个安全组")

        risk_assessment = self.audit_data.get('risk_assessment', {})
        print(f"\n🚨 安全风险评估:")
        print(f"   总体风险等级: {risk_assessment.get('overall_risk_level', '未知')}")
        print(f"   风险评分: {risk_assessment.get('risk_score', 0)}")
        print(f"   风险分布: 严重({stats['critical_risks']}) 高({stats['high_risks']}) 中({stats['medium_risks']}) 低({stats['low_risks']})")

        print(f"\n📁 生成的报告文件:")
        print(f"   📊 HTML综合报告: {self.report_dir}/comprehensive_security_report.html")
        print(f"   💾 JSON详细数据: {self.report_dir}/comprehensive_audit_report.json")
        print(f"   📋 风险评估: {self.report_dir}/risk_assessment.json")
        print(f"   📄 CSV报告: {self.report_dir}/*.csv")

        recommendations = risk_assessment.get('recommendations', [])
        if recommendations:
            print(f"\n💡 优先修复建议:")
            for i, rec in enumerate(recommendations[:3], 1):
                print(f"   {i}. {rec['title']} ({rec['priority']})")
                print(f"      {rec['description']}")

        print(f"\n⚠️  重要提醒:")
        print(f"   • 本次审计可能已在CloudTrail中记录，请注意日志安全")
        print(f"   • 建议立即轮换用于审计的访问密钥")
        print(f"   • 定期执行安全审计以持续改进安全态势")

        print("\n" + "=" * 100)
        print("✅ 审计完成！请查看生成的报告文件获取详细信息。")
        print("=" * 100)

def main():
    """主函数"""
    print("🚀 AWS综合安全审计工具")
    print("=" * 60)
    print("⚠️  警告：此工具会进行全面的AWS环境审计")
    print("⚠️  请确保在授权环境中使用，并了解相关风险")
    print("⚠️  审计过程取决于账户规模与权限")

    # 获取AWS凭证（可改为从环境变量读取）
    print("\n📝 请输入AWS访问凭证:")
    access_key_id = input("AWS Access Key ID: ").strip()
    secret_access_key = input("AWS Secret Access Key: ").strip()

    if not access_key_id or not secret_access_key:
        print("❌ 请提供有效的AWS凭证")
        sys.exit(1)

    # 选择审计区域
    print("\n🌍 选择审计区域 (多个区域用逗号分隔，直接回车使用默认区域):")
    print("   推荐区域: us-east-1, us-west-2, ap-northeast-1, eu-west-1")
    regions_input = input("区域列表 [us-east-1,us-west-2]: ").strip()

    if regions_input:
        regions_raw = regions_input.replace('[', '').replace(']', '').replace(' ', '')
        regions = [r.strip() for r in regions_raw.split(',') if r.strip()]
        valid_regions = []
        for region in regions:
            if region and '-' in region and len(region.split('-')) >= 3:
                valid_regions.append(region)
            else:
                print(f"⚠️  跳过无效区域格式: {region}")
        if not valid_regions:
            print("❌ 没有有效的区域，使用默认区域")
            regions = ['us-east-1', 'us-west-2']
        else:
            regions = valid_regions
    else:
        regions = ['us-east-1', 'us-west-2']

    print(f"\n✅ 将在以下区域进行审计: {', '.join(regions)}")

    # 确认开始审计
    print(f"\n⚠️  即将开始AWS综合安全审计:")
    print(f"   • Access Key: {access_key_id[:8]}...{access_key_id[-4:]}")
    print(f"   • 审计区域: {', '.join(regions)}")
    print(f"   • 审计内容: 权限测试、资源枚举、安全分析、风险评估")
    confirm = input(f"\n确认开始审计? (输入 'YES' 继续): ").strip()
    if confirm != 'YES':
        print("审计已取消")
        sys.exit(0)

    try:
        auditor = AWSComprehensiveAuditor(access_key_id, secret_access_key, regions)
        if not auditor.test_identity_and_permissions():
            print("❌ 身份验证失败，审计终止")
            sys.exit(1)
        auditor.enumerate_all_resources()
        auditor.analyze_security_risks()

        # 可选：危险权限测试（写操作）
        do_danger = input("\n是否进行【危险权限测试】(创建/删除临时IAM用户/角色)? 输入 'DOIT' 执行，其他跳过：").strip()
        if do_danger == 'DOIT':
            auditor.test_dangerous_permissions()

        auditor.generate_comprehensive_report()
        auditor.generate_final_summary()
    except KeyboardInterrupt:
        print("\n\n⚠️  审计被用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ 审计过程中发生错误: {e}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
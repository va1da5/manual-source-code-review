# Source Code Review Bug Patterns

This repository contains Regex patterns to look for while performing manual application source code analysis. The patterns are pretty open-scoped and, if used in automated tools, would provide lots of false-positives. However, it still brings value when doing manual investigation and could lead into some serious bug findings. The match of the pattern in the code does not necessarily mean the application being vulnerable to a certain type of attack. It is security tester's responsibility to evaluate each case and arrive to the conclusion.

## Tools

Usage with `grep`

```bash
# List files with a specific extension
find . -name "*.html" -o -name "*.jsp"

grep -rnw -P "do(?:Post|Get|Put|Patch|Delete|Options|Copy|Move)\b" -l | grep -vP ".*.(?:js|css|jpg)$" |  xargs grep -iP "WHERE.*" --color
```

---

## Javascript

### Node JS

```regex
unserialize\s*\(
eval\s*\(
\bchild_process\b
exec\s*\(
spawn\s*\(
execFile\s*\(
\bfork\s*\(
```

### HTML DOM Related

```regex
innerText
innerHTML
document\.location
document\.create
document\.URL
document\.URLUnencoded
document\.referrer
window\.location
document\.write\s*\(
document\.writeln\s*\(
document\.body\.innerHtml
eval\s*\(
document\.cookie
window\.execScript\s*\(
window\.setInterval\s*\(
window\.setTimeout\s*\(
document\.location
document\.URL
document\.open\s*\(
window\.location\.href
window.navigate\s*\(
window\.open\s*\(
document\.execCommand
location\.hash
location\.href
window\.createRequest
document\.attachEvent
window\.execScript
window\.setInterval
target\s*=\s*["']_blank['"]
```

---

## PHP

### PHP Deserialization

```regex
unserialize\s?\(
unserialize_callback_func
```

### Command Execution

```regex
exec\s*\(
passthru\s*\(
popen\s*\(
shell_exec\s*\(
system\s*\(
`[^`]+`
eval\s*\(
proc_open\s*\(
proc_close\s*\(
proc_get_status\s*\(
proc_nice\s*\(
proc_terminate\s*\(
```

### User Input

```regex
\$_ENV\[.*\]
\$_GET\[.*\]
\$_POST\[.*\]
\$_COOKIE\[.*\]
\$_REQUEST\[.*\]
\$_FILES\[.*\]
\$_SERVER\[.*\]
\$HTTP_GET_VARS
\$http_get_vars
\$HTTP_POST_VARS
\$http_post_vars
\$HTTP_ENV_VARS
\$http_env_vars
\$HTTP_RAW_POST_DATA
\$http_raw_post_data
\$HTTP_POST_FILES
\$http_post_files
```

### SQL Commands

```regex
mysql_query\s*\(
WHERE\s+.*=.*
mysql_connect\s*\(
mysql_pconnect\s*\(
mysqli\s*\(
(mysqli::[^ ]*|mysqli_[^ ]*)
mysql_query\s*\(
mysql_error\s*\(
pg_connect\s*\(
pg_pconnect\s*\(
pg_execute\s*\(
pg_insert\s*\(
pg_put_line\s*\(
pg_query\s*\(
pg_select\s*\(
pg_send_query\s*\(
pg_update\s*\(
sqlite_open\s*\(
sqlite_query\s*\(
sqlite_array_query\s*\(
sqlite_create_function\s*\(
sqlite_create_aggregate\s*\(
sqlite_exec\s*\(
sqlite_fetch_.*
msql_.*
mssql_.*
odbc_.*
fbsql_.*
db2_.*
sqlsrv_.*
sybase_.*
ibase_.*
dbx_.*
ingres_.*
ifx_.*
oci_.*
px_.*
ovrimos_.*
maxdb_.*
```

### File Related Functions

```regex
(include|include_once|require|require_once)
file\s*\(
file_get_contents\s*\(
fopen\s*\(
p?fsockopen\s*\(
fwrite\s*\(
move_uploaded_file
stream_.*
readfile\s*\(
```

### Other Interesting Stuff

```regex
get_loaded_extensions
getenv\s?\(
putenv\s?\(
apache_setenv\s?\(
apache_request_headers\s?\(
apache_response_headers\s?\(
header\s?\(
stream_context_create
create_function\s?\(
mail\s?\(
preg_replace
\<\?\=\$(_ENV|_GET|_POST|_COOKIE|_REQUEST|_SERVER|HTTP|http)
\<\%\=\$(_ENV|_GET|_POST|_COOKIE|_REQUEST|_SERVER|HTTP|http)
{php}
```

### I/O Streams

```regex
php://stdin
php://stdout
php://stderr
php://output
php://input
php://filter
php://memory
php://temp
```

---

## JAVA

- [FindBugs JAVA weaknesses database](https://find-sec-bugs.github.io/bugs.htm)
- [Sonarqube Rules](https://rules.sonarsource.com/java)
- [PMD Java Coding Patterns](https://pmd.github.io/pmd-6.18.0/pmd_rules_java.html)
- [Java-Deserialization-Cheat-Sheet](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)

### Deserialization

```regex
\bObjectInputStream\(
\breadObject\(
\bdefaultReadObject\s*\(
\breadUnshared\s*\(
\breadResolve\s*\(
\bwriteObject\s*\(
\bXMLDecoder\s*\(
\bXStream\b
\.enableDefaultTyping\(\)
\bcom\.fasterxml\.jackson\.databind\.ObjectMapper\b
\bnew\s+ObjectMapper()\b
\b@JsonTypeInfo\(
\breadValue\([^,]+,\s*Object\.class\)
\bJSON\.parseObject\b
\bcom\.alibaba\.fastjson\.JSON\b
```

### Command Execution

```regex
\bexec\s?\(
```

### User Input

```regex
do(?:Post|Get|Put|Patch|Delete|Options|Copy|Move)\b
@WebServlet\(.*
\bjavax\.servlet\..*
getParameter\s*\(
getParameterNames\s*\(
getParameterValues\s*\(
getParameterMap\s*\(
getQueryString\s*\(
HttpServletRequest
getScheme\s*\(
getProtocol\s*\(
getContentType\s*\(
getServerName\s*\(
getRemoteAddr\s*\(
getRemoteHost\s*\(
getRealPath\s*\(
getLocalName\s*\(
getAttribute\s*\(
getAttributeNames\s*\(
getLocalAddr\s*\(
getAuthType\s*\(
getRemoteUser\s*\(
getCookies\s*\(
getHeaderNames\s*\(
getHeaders?\s*\(
getPrincipal\s*\(
getUserPrincipal\s*\(
getRequestedSessionId\s*\(
XMLReader
\bCookie\b
getRequestURI
getRequestURL
getComment\s*\(

\.get(?:Parameter(?:Names?|Values?|Map)?|QueryString|ContentType|Cookies|Header(?:s|Names)|Request(?:URL|URI))\s*\(
```

### JSP

```regex
\brequest\.getParameter\(
\bsession\.setAttribute\(
\$\{[^}]+\}
\.getRequestDispatcher\(                                        #look for .include(request, response)
(?!.*\.jspf?['"])(?:<jsp:include\s+page|<jsp:directive\.include\s+file|<%@\s+include\s+file|<c:import\s+url)\s*=\s*["'].*
<c:out.*escapeXml\s*=\s*["']false["']
<%=\s+[a-zA-Z0-9_$]+\s+%>
<x:transform\b.*\b(?:xml|xslt)\s*=.*(?:xml|xslt)\s*=.*>

```

### Servlet Response Functions

```regex
\.sendRedirect\((?:.*\.getParameter\(.*\))?
setJavaScriptEnabled
getWriter
addCookie\s*\(
\b(?:add|set)Header\s*\(
\bsetStatus
setAttribute\s*\(
HttpServletResponse
ServletOutputStream
\.addHeader\("Access-Control-Allow-Origin", "\*"\)
```

### SQL Commands

```regex
execute(?:Query|Update)\s*\(
Prepared?Statement\b
\b(?:SELECT|UPDATE|DELETE|WHERE|GROUP BY|HAVING|ORDER BY)\s+.*=.*
(?:create|execute)[sS]tatement\s*\(
get(?:Object|String)\s*\(
addBatch\s*\(
execute\s*\(
prepareCall\s*\(
jdbc:.*
```

### Files/Streams Related Functions

```regex
\bcreateRequest\b
\b(?:new )?File\b
\bFiles\.exists\((?:\s*Paths\.get\()?
\bfromFile\s*\(
java\.io\.File
\bFileReader\b
\bFileWriter\b
renameTo\s*\(
mkdir\s*\(
\bRandomAccessFile\b
\bFileOutputStream\b
\bHttpsURLConnection\b
\bFileInputStream\b
\bFilterInputStream\b
\bPipedInputStream\b
\bBufferedReader\b
\bFileOutputStream\b
\bSequenceInputStream\b
\bStringBufferInputStream\b
\bByteArrayInputStream\b
\bSocket\s*\(
\bServerSocket\s*\(
\bFileNotFoundException\b
(?:\bnew\s+URL(.*))?\.(?:getContent|open(?:Connection|Stream))\(\)
```

### XXE

```regex
\.createXMLStreamReader\s*\(
(?<!Pattern|RegExp|JsonPointer)(?:XPathExpression\b.*)?\.compile\s*\(
(?:\bSAXParser\b.*)?\.newSAXParser\s*\(\b                                # look for parser.parse(..)
(?:\bXMLReader\b.*)?\.createXMLReader\s*\(                               # look for reader.parse(...);
(?:\bDocumentBuilder\b.*)?\.newDocumentBuilder\s*\(                      # look for db.parse(input);
\bDocument\s.*\.parse\s*\(
(?:\bTransformer\s.*)?\.newTransformer\s*\(
```

### Spring

```regex
@(?:Request|Get|Post|Put|Delete|Patch)Mapping
\.csrf\(\)\.disable\(\)
\bExpression\s.*\.parseExpression\s*\(
redirect\(\s*@RequestParam\(.*
\bModelAndView\(
<spring:eval\s*expression\s*=\s*"
```

### Other Interesting Stuff

```regex
\bRandom\(
getPropert(y|ies)\s*\(
getSession\s*\(
\bHTTPCookie\b
\bdoPrivileged\b
IS_SUPPORTING_EXTERNAL_ENTITIES
eval\s*\(
\bprint[Ss]tack[Tt]race\b
Base64
\.newTransformer\(
import java\.lang\.Runtime
\bXPath\b
(?:\bXPath\s.*)\.newXPath\s*\(
(?:\bXPathExpression\s.*)\.compile\s*\(
\bNamingEnumeration\b.*\.search\s*\(
(?:\bScriptEngine\s.*)?\.getEngineByName\s*\(
(?!.*=\s*"\s*\+.*\+\s*")(?:String\s*)?(?:secret|token|pass(?:key|phrase|word|wd)?|api_?key|hash|user(?:name|id)?|login|admin|account(?:id)?|auth|email)[a-zA-Z0-9$_]*\s*=\s*".{4,}";
\.newTransformer\s*\(
Velocity\.evaluate\(
BeanUtils\.populate\(
\bMimeMessage\(
\.setEscapeModelStrings\(false\)
(?:setHeader|setRequestProperty)\("Authorization"\s*,\s*"Basic
\bisActiveSession\([a-z0-9_$]+\.getRequestedSessionId\(\)\)
\bTemplate\s+[a-zA-Z0-9_$]+\s*=\s*[a-zA-Z0-9_$]+.getTemplate\(
```

---

## C#

- [Security Code Scan Rules](https://security-code-scan.github.io/#Rules)

### Deserialization

```regex
XmlReader
XmlReader\.Create
XamlReader\.Load
JsonConvert.DeserializeObject
\.DeserializeObject
JSON.ToObject
\.ToObject
JsonSerializer
JavaScriptSerializer
SimpleTypeResolvers\s*\(
XmlSerializer\s*\(
DataContractSerializer\s*\(
DeserializerBuilder
\.Deserialize\s*\(
BinaryFormatter
ObjectStateFormatter
SoapFormatter
NetDataContractSerializer
LosFormatter
SerializationFormatter
```

### Command Execution

```regex
Server\.Execute
\bExecute\b
\bEval\b
\bProcess\b
\.StartInfo\.FileName\b
\.StartInfo\.Arguments\b

```

### User Input

```regex
System\.Net\.Cookie
Cookie
\.Cookies
request\.cookies
Request
Request\.Files
Request\.Headers
request\.querystring
request\.form
request\.item
request\.url
request\.urlreferrer
request\.useragent
request\.userlanguages
```

### Server Response Functions

```regex
response\.write
innerText
HttpUtility
innerHTML
HtmlEncode
<%=
UrlEncode
document\.cookie
HTTPOnly
htmlcontrols\.
webcontrols\.
Response\.AddHeader
Response\.Redirect
```

### SQL Commands

```regex
\bselect\b
\bdelete\b
\bupdate\b
\bwhere.*=.*

sp_executesql
\bExecuteQuery\b
\bexecuteSQL\b
\bexecuteQuery\b
\bSqlDataAdapter\b
\bSqlConnection\b
\bCreateSQLQuery\b
exec sp_
exec xp_
execute sp_
exec @
setfilter
sqloledb
\.Provider\b
ExecuteReader\b
SqlDataReader\b
execute @
System\.Data\.sql
DataSource
ExecuteReader
executestatement
GetQueryResultInXML
\bdriver\b
ADODB\.recordset
SqlCommand
SqlDataAdapter
\badodb\b
Server\.CreateObject
New OleDbConnection\b
\bOdbcCommand\b
\bSqlCommand\b
Microsoft\.Jet
\bStoredProcedure\b
\bExecuteSqlCommand\b
\bExecuteDataSet\b
\bNpgsqlCommand\b
```

### Files/Streams Related Functions

```regex
System\.IO
ReadAllBytes
FileSystemObject
StreamReader
FileInputStream
GetTempFileName
```

### XXE

```regex
\bXmlReaderSettings\b
\bXmlReader\b
\bXmlDocument\b
```

### Other Interesting Stuff

```regex
Shell\.Application
Shell32
Server\.CreateObject
\.Run\b
Wscript\.Shell
System\.Security\.Cryptography
\bCipherMode\.(CBC|ECB|OFB)
\.SetPassword\b
```

---

## References

- [Regular Expression: Special Groups](https://www.regular-expressions.info/refadv.html)
- [graudit](https://github.com/wireghoul/graudit)
- [Security Code Scan - static code analyzer for .NET](https://security-code-scan.github.io/)
- [FindBugs JAVA weaknesses database](https://find-sec-bugs.github.io/bugs.htm)
- [Sonarqube Rules](https://rules.sonarsource.com/java)
- [PMD Java Coding Patterns](https://pmd.github.io/pmd-6.18.0/pmd_rules_java.html)
- [Java-Deserialization-Cheat-Sheet](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)
- [CFR - another java decompiler](http://www.benf.org/other/cfr/)
- [JD-GUI](https://java-decompiler.github.io/)

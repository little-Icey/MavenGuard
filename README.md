# MavenGuard
Malicious Maven Packages Detector using Graph Representation Learning and Static Analysis.

# Some details

## Mapping relationship between sensitive API and behavior types

| 大类名称 (categoryName) | 细粒度分类 (subcategoryName) | 编号 (short) | API 签名 (apiNames) |
| --- | --- | --- | --- |
| **Sensitive Information Reading**<br>

<br>(敏感信息读取) | Retrieve environment variable | i1 | `<java.lang.System: java.lang.String getenv(java.lang.String)>``<java.lang.System: java.util.Map getenv()>` |
| **Network Operation**<br>

<br>(网络操作) | Create a socket or network connection | n1 | `<java.net.URL: java.net.URL <init>(java.lang.String)>``<java.net.URL: void <init>(java.lang.String)>``<java.net.Socket: void <init>(java.net.InetAddress,int)>``<java.net.ServerSocket: void <init>()>``<java.net.ServerSocket: void <init>(int)>``<java.net.ServerSocket: void <init>(int,int)>``<java.net.ServerSocket: void <init>(int,int,java.net.InetAddress)>``<java.net.InetSocketAddress: void <init>(int)>``<java.net.InetSocketAddress: void <init>(java.net.InetAddress,int)>``<java.net.InetSocketAddress: void <init>(java.lang.String,int)>``<java.net.InetSocketAddress: void <init>(int,java.lang.String)>` |
|  | Check connection status | n2 | `<java.net.Socket: void setConnected()>``<java.net.Socket: boolean isConnected()>``<java.net.Socket: boolean isBound()>``<java.net.Socket: void close()>``<java.net.ServerSocket: java.net.Socket accept()>` |
|  | Connect to socket or url | n3 | `<java.net.URL: java.net.URLConnection openConnection()>``<java.net.Socket: void connect(java.net.SocketAddress, int)>``<java.net.Socket: void connect(java.net.SocketAddress)>``<java.net.ServerSocket: java.net.Socket accept()>` |
|  | Resolve the hostname or IP address | n4 | `<java.net.Socket: java.net.InetAddress getInetAddress()>``<java.net.InetAddress: java.net.InetAddress getByName(java.lang.String)>``<java.net.InetAddress: java.net.InetAddress getByName(java.lang.String,java.net.InetAddress)>``<java.net.InetAddress: java.net.InetAddress[] getAllByName(java.lang.String)>``<java.net.InetAddress: java.net.InetAddress[] getAllByName(java.lang.String,java.net.InetAddress)>``<java.net.InetAddress: java.net.InetAddress getByAddress(java.lang.String,byte[])>``<java.net.InetAddress: java.net.InetAddress getByAddress(byte[])>` |
|  | Send data over the network | n5 | `<java.net.URLConnection: java.io.OutputStream getOutputStream()>``<java.net.Socket: java.io.OutputStream getOutputStream()>` |
|  | Receive data over the network | n6 | `<java.net.URL: java.io.InputStream openStream()>``<java.net.URLConnection: java.io.InputStream getInputStream()>``<java.net.Socket: java.io.InputStream getInputStream()>` |
| **File Operation**<br>

<br>(文件操作) | Create an input stream | f1 | `<java.io.BufferedReader: void <init>(java.io.Reader,int)>``<java.io.BufferedReader: void <init>(java.io.Reader)>``<java.io.FileInputStream: void <init>(java.io.File)>` |
|  | Create an output stream | f2 | `<java.io.FileWriter: void <init>(java.lang.String,boolean)>``<java.io.BufferedWriter: void <init>(java.io.Writer)>``<java.io.FileOutputStream: void <init>(java.lang.String)>``<java.io.FileOutputStream: void <init>(java.lang.String,boolean)>``<java.io.FileOutputStream: void <init>(java.io.File)>``<java.io.FileOutputStream: void <init>(java.io.File,boolean)>``<java.io.FileOutputStream: void <init>(java.io.FileDescriptor)>` |
|  | Write data | f3 | `<java.io.BufferedWriter: void write(int)>``<java.io.BufferedWriter: void write(char[],int,int)>``<java.io.BufferedWriter: void write(java.lang.String)>``<java.io.BufferedWriter: void write(java.lang.String,int,int)>``<java.io.FileOutputStream: void write(byte[],int,int)>``<java.io.FileOutputStream: void write(byte[])>``<java.io.FileOutputStream: void write(int)>``<java.io.FileOutputStream: void writeBytes(byte[],int,int,boolean)>``<java.io.RandomAccessFile: void write(int)>``<java.io.RandomAccessFile: void write(byte[])>``<java.io.RandomAccessFile: void writeBytes(byte[],int,int)>``<java.io.RandomAccessFile: void writeBytes(java.lang.String)>` |
|  | Read data | f4 | `<java.io.BufferedReader: java.lang.String readLine(boolean)>``<java.io.BufferedReader: java.lang.String readLine()>``<java.io.BufferedReader: int read()>``<java.io.BufferedReader: int read(char[],int,int)>``<java.io.FileInputStream: int read()>``<java.io.FileInputStream: int read(byte[])>``<java.io.FileInputStream: int read(byte[],int,int)>``<java.io.RandomAccessFile: int read(byte[])>``<java.io.RandomAccessFile: int read(byte[],int,int)>``<java.io.RandomAccessFile: int readBytes(byte[],int,int)>``<java.io.RandomAccessFile: void readFully(byte[])>``<java.io.RandomAccessFile: java.lang.String readLine()>``<java.io.RandomAccessFile: java.lang.String readUTF()>` |
|  | Create a file or directory | f5 | `<java.io.File: java.io.File createTempFile(java.lang.String,java.lang.String,java.io.File)>``<java.io.File: java.io.File createTempFile(java.lang.String,java.lang.String)>``<java.io.File: boolean createNewFile()>` |
|  | Delete a file or directory | f6 | `<java.io.File: boolean delete()>` |
|  | Retrieve file or directory information | f7 | `<java.io.File: boolean exists()>``<java.io.File: java.io.File[] listFiles()>``<java.io.File: java.lang.String[] list()>``<java.io.File: java.lang.String getName()>` |
|  | Close a file or stream | f8 | `<java.io.BufferedWriter: void close()>``<java.io.FileOutputStream: void close()>` |
| **Command Execution**<br>

<br>(命令执行) | Execute the specified command as a separate process | c1 | `<java.lang.Runtime: java.lang.Runtime getRuntime()>``<java.lang.Runtime: java.lang.Process exec(java.lang.String)>``<java.lang.Runtime: java.lang.Process exec(java.lang.String,java.lang.String[])>``<java.lang.Runtime: java.lang.Process exec(java.lang.String,java.lang.String[],java.io.File)>``<java.lang.Runtime: java.lang.Process exec(java.lang.String[])>``<java.lang.Runtime: java.lang.Process exec(java.lang.String[],java.lang.String[])>``<java.lang.Runtime: java.lang.Process exec(java.lang.String[],java.lang.String[],java.io.File)>` |
|  | Create a new process builder | c2 | `<java.lang.ProcessBuilder: void <init>()>``<java.lang.ProcessBuilder: void <init>(java.lang.List<java.lang.String>)>``<java.lang.ProcessBuilder: void <init>(java.lang.String[])>` |
|  | Spawn a new process | c3 | `<java.lang.ProcessBuilder: java.lang.Process start()>` |
|  | Load dynamic library | c4 | `<java.lang.System: void load(java.lang.String)>``<java.lang.System: void loadLibrary(java.lang.String)>` |
| **Script Evaluation**<br>

<br>(脚本解析与执行) | Create a new script parser | s1 | `<javax.script.ScriptEngineManager: void <init>()>``<javax.script.ScriptEngineManager: javax.script.ScriptEngine getEngineByName(java.lang.String)>``<org.springframework.expression.spel.standard.SpelExpressionParser: void <init>()>``<org.springframework.expression.spel.standard.SpelExpressionParser: void <init>(org.springframework.expression.spel.SpelParserConfiguration)>` |
|  | Parse an expression | s2 | `<org.springframework.expression.spel.standard.SpelExpressionParser: org.springframework.expression.spel.standard.SpelExpression parseRaw(java.lang.String)>``<org.springframework.expression.spel.standard.SpelExpressionParser: org.springframework.expression.spel.standard.SpelExpression doParseExpression(java.lang.String,org.springframework.expression.ParserContext)>``<org.springframework.expression.spel.standard.SpelExpressionParser: org.springframework.expression.Expression doParseExpression(java.lang.String,org.springframework.expression.ParserContext)>` |
|  | Evaluate a script | s3 | `<groovy.lang.GroovyShell: java.lang.Object evaluate(java.lang.String)>``<javax.script.ScriptEngine Object eval(java.lang.String)>``<java.beans.Expression: void execute()>``<java.beans.Statement: void execute()>` |
| **Cryptography & Data Encoding/Decoding**<br>

<br>(加解密与编解码) | Cipher the data | d1 | `<java.util.Base64: java.util.Base64$Encoder getUrlEncoder()>``<java.util.Base64: java.util.Base64$Encoder getEncoder()>``<javax.crypto.Cipher: javax.crypto.Cipher getInstance(java.lang.String)>` |
|  | Decipher the data | d2 | `<java.util.Base64: java.util.Base64$Decoder getDecoder()>` |
| **Reflection**<br>

<br>(反射操作) | Invoke a method | r1 | `<java.lang.reflect.Method: java.lang.Object invoke(java.lang.Object,java.lang.Object[])>` |
|  | Load and get the Class object | r2 | `<java.lang.ClassLoader: java.lang.Class defineClass(byte[],int,int)>``<java.lang.ClassLoader: java.lang.Class defineClass(java.lang.String,byte[],int,int)>``<java.lang.ClassLoader: java.lang.Class loadClass(java.lang.String)>``<java.lang.ClassLoader: java.lang.Class loadClass(java.lang.String,boolean)>``<java.net.URLClassLoader: java.lang.Class findClass(java.lang.String)>``<java.lang.Class: java.lang.Class forName(java.lang.String)>``<java.lang.Class: java.lang.Class forName(java.lang.String,boolean,java.lang.ClassLoader)>` |
|  | Get the Method object | r3 | `<java.lang.Class: java.lang.reflect.Method[] getDeclaredMethods()>``<java.lang.Class: java.lang.reflect.Method getDeclaredMethod(java.lang.String,java.lang.Class[])>``<java.lang.Class: java.lang.reflect.Method getMethod(java.lang.String,java.lang.Class[])>` |
|  | Get the field object | r4 | `<java.lang.Class: java.lang.reflect.Field[] getDeclaredFields()>``<java.lang.Class: java.lang.reflect.Field getDeclaredField(java.lang.String)>``<java.lang.Class: java.lang.reflect.Field getField(java.lang.String)>``<java.lang.Class: java.lang.reflect.Field[] getFields()>``<java.lang.reflect.Field: java.lang.Object get(java.lang.Object)>` |
|  | Get constructor | r5 | `<java.lang.Class: java.lang.reflect.Constructor getConstructor(java.lang.Class[])>``<java.lang.reflect.Constructor: java.lang.Class[] getParameterTypes()>` |
|  | Create a new instance | r6 | `<java.lang.Class: java.lang.Object newInstance()>``<java.lang.reflect.Constructor: java.lang.Object newInstance(java.lang.Object[])>``<java.net.URLClassLoader: java.net.URLClassLoader newInstance(java.net.URL[],java.lang.ClassLoader)>``<java.net.URLClassLoader: java.net.URLClassLoader newInstance(java.net.URL[])>` |
|  | Initial a new classloader | r7 | `<java.lang.Class: java.lang.ClassLoader getClassLoader()>``<java.net.URLClassLoader: void <init>(java.net.URL[],java.lang.ClassLoader)>``<java.net.URLClassLoader: void <init>(java.net.URL[])>` |

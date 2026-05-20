# MavenGuard
Malicious Maven Packages Detector using Graph Representation Learning and Static Analysis.

# Some details

## Mapping relationship between sensitive API and behavior types

<table>
  <thead>
    <tr>
      <th>categoryName</th>
      <th>subcategoryName</th>
      <th>apiNames</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td rowspan="1">Sensitive Information Reading</td>
      <td>Retrieve environment variable</td>
      <td>
        <code>&lt;java.lang.System: java.lang.String getenv(java.lang.String)&gt;</code><br>
        <code>&lt;java.lang.System: java.util.Map getenv()&gt;</code>
      </td>
    </tr>

    <tr>
      <td rowspan="6">Network Operation</td>
      <td>Create a socket or network connection</td>
      <td>
        <code>&lt;java.net.URL: java.net.URL &lt;init&gt;(java.lang.String)&gt;</code><br>
        <code>&lt;java.net.URL: void &lt;init&gt;(java.lang.String)&gt;</code><br>
        <code>&lt;java.net.Socket: void &lt;init&gt;(java.net.InetAddress,int)&gt;</code><br>
        <code>&lt;java.net.ServerSocket: void &lt;init&gt;()&gt;</code><br>
        <code>&lt;java.net.ServerSocket: void &lt;init&gt;(int)&gt;</code><br>
        <code>&lt;java.net.ServerSocket: void &lt;init&gt;(int,int)&gt;</code><br>
        <code>&lt;java.net.ServerSocket: void &lt;init&gt;(int,int,java.net.InetAddress)&gt;</code><br>
        <code>&lt;java.net.InetSocketAddress: void &lt;init&gt;(int)&gt;</code><br>
        <code>&lt;java.net.InetSocketAddress: void &lt;init&gt;(java.net.InetAddress,int)&gt;</code><br>
        <code>&lt;java.net.InetSocketAddress: void &lt;init&gt;(java.lang.String,int)&gt;</code><br>
        <code>&lt;java.net.InetSocketAddress: void &lt;init&gt;(int,java.lang.String)&gt;</code>
      </td>
    </tr>
    <tr>
      <td>Check connection status</td>
      <td>
        <code>&lt;java.net.Socket: void setConnected()&gt;</code><br>
        <code>&lt;java.net.Socket: boolean isConnected()&gt;</code><br>
        <code>&lt;java.net.Socket: boolean isBound()&gt;</code><br>
        <code>&lt;java.net.Socket: void close()&gt;</code><br>
        <code>&lt;java.net.ServerSocket: java.net.Socket accept()&gt;</code>
      </td>
    </tr>
    <tr>
      <td>Connect to socket or url</td>
      <td>
        <code>&lt;java.net.URL: java.net.URLConnection openConnection()&gt;</code><br>
        <code>&lt;java.net.Socket: void connect(java.net.SocketAddress, int)&gt;</code><br>
        <code>&lt;java.net.Socket: void connect(java.net.SocketAddress)&gt;</code><br>
        <code>&lt;java.net.ServerSocket: java.net.Socket accept()&gt;</code>
      </td>
    </tr>
    <tr>
      <td>Resolve the hostname or IP address</td>
      <td>
        <code>&lt;java.net.Socket: java.net.InetAddress getInetAddress()&gt;</code><br>
        <code>&lt;java.net.InetAddress: java.net.InetAddress getByName(java.lang.String)&gt;</code><br>
        <code>&lt;java.net.InetAddress: java.net.InetAddress getByName(java.lang.String,java.net.InetAddress)&gt;</code><br>
        <code>&lt;java.net.InetAddress: java.net.InetAddress[] getAllByName(java.lang.String)&gt;</code><br>
        <code>&lt;java.net.InetAddress: java.net.InetAddress[] getAllByName(java.lang.String,java.net.InetAddress)&gt;</code><br>
        <code>&lt;java.net.InetAddress: java.net.InetAddress getByAddress(java.lang.String,byte[])&gt;</code><br>
        <code>&lt;java.net.InetAddress: java.net.InetAddress getByAddress(byte[])&gt;</code>
      </td>
    </tr>
    <tr>
      <td>Send data over the network</td>
      <td>
        <code>&lt;java.net.URLConnection: java.io.OutputStream getOutputStream()&gt;</code><br>
        <code>&lt;java.net.Socket: java.io.OutputStream getOutputStream()&gt;</code>
      </td>
    </tr>
    <tr>
      <td>Receive data over the network</td>
      <td>
        <code>&lt;java.net.URL: java.io.InputStream openStream()&gt;</code><br>
        <code>&lt;java.net.URLConnection: java.io.InputStream getInputStream()&gt;</code><br>
        <code>&lt;java.net.Socket: java.io.InputStream getInputStream()&gt;</code>
      </td>
    </tr>

    <tr>
      <td rowspan="8">File Operation</td>
      <td>Create an input stream</td>
      <td>
        <code>&lt;java.io.BufferedReader: void &lt;init&gt;(java.io.Reader,int)&gt;</code><br>
        <code>&lt;java.io.BufferedReader: void &lt;init&gt;(java.io.Reader)&gt;</code><br>
        <code>&lt;java.io.FileInputStream: void &lt;init&gt;(java.io.File)&gt;</code>
      </td>
    </tr>
    <tr>
      <td>Create an output stream</td>
      <td>
        <code>&lt;java.io.FileWriter: void &lt;init&gt;(java.lang.String,boolean)&gt;</code><br>
        <code>&lt;java.io.BufferedWriter: void &lt;init&gt;(java.io.Writer)&gt;</code><br>
        <code>&lt;java.io.FileOutputStream: void &lt;init&gt;(java.lang.String)&gt;</code><br>
        <code>&lt;java.io.FileOutputStream: void &lt;init&gt;(java.lang.String,boolean)&gt;</code><br>
        <code>&lt;java.io.FileOutputStream: void &lt;init&gt;(java.io.File)&gt;</code><br>
        <code>&lt;java.io.FileOutputStream: void &lt;init&gt;(java.io.File,boolean)&gt;</code><br>
        <code>&lt;java.io.FileOutputStream: void &lt;init&gt;(java.io.FileDescriptor)&gt;</code>
      </td>
    </tr>
    <tr>
      <td>Write data</td>
      <td>
        <code>&lt;java.io.BufferedWriter: void write(int)&gt;</code><br>
        <code>&lt;java.io.BufferedWriter: void write(char[],int,int)&gt;</code><br>
        <code>&lt;java.io.BufferedWriter: void write(java.lang.String)&gt;</code><br>
        <code>&lt;java.io.BufferedWriter: void write(java.lang.String,int,int)&gt;</code><br>
        <code>&lt;java.io.FileOutputStream: void write(byte[],int,int)&gt;</code><br>
        <code>&lt;java.io.FileOutputStream: void write(byte[])&gt;</code><br>
        <code>&lt;java.io.FileOutputStream: void write(int)&gt;</code><br>
        <code>&lt;java.io.FileOutputStream: void writeBytes(byte[],int,int,boolean)&gt;</code><br>
        <code>&lt;java.io.RandomAccessFile: void write(int)&gt;</code><br>
        <code>&lt;java.io.RandomAccessFile: void write(byte[])&gt;</code><br>
        <code>&lt;java.io.RandomAccessFile: void writeBytes(byte[],int,int)&gt;</code><br>
        <code>&lt;java.io.RandomAccessFile: void writeBytes(java.lang.String)&gt;</code>
      </td>
    </tr>
    <tr>
      <td>Read data</td>
      <td>
        <code>&lt;java.io.BufferedReader: java.lang.String readLine(boolean)&gt;</code><br>
        <code>&lt;java.io.BufferedReader: java.lang.String readLine()&gt;</code><br>
        <code>&lt;java.io.BufferedReader: int read()&gt;</code><br>
        <code>&lt;java.io.BufferedReader: int read(char[],int,int)&gt;</code><br>
        <code>&lt;java.io.FileInputStream: int read()&gt;</code><br>
        <code>&lt;java.io.FileInputStream: int read(byte[])&gt;</code><br>
        <code>&lt;java.io.FileInputStream: int read(byte[],int,int)&gt;</code><br>
        <code>&lt;java.io.RandomAccessFile: int read(byte[])&gt;</code><br>
        <code>&lt;java.io.RandomAccessFile: int read(byte[],int,int)&gt;</code><br>
        <code>&lt;java.io.RandomAccessFile: int readBytes(byte[],int,int)&gt;</code><br>
        <code>&lt;java.io.RandomAccessFile: void readFully(byte[])&gt;</code><br>
        <code>&lt;java.io.RandomAccessFile: java.lang.String readLine()&gt;</code><br>
        <code>&lt;java.io.RandomAccessFile: java.lang.String readUTF()&gt;</code>
      </td>
    </tr>
    <tr>
      <td>Create a file or directory</td>
      <td>
        <code>&lt;java.io.File: java.io.File createTempFile(java.lang.String,java.lang.String,java.io.File)&gt;</code><br>
        <code>&lt;java.io.File: java.io.File createTempFile(java.lang.String,java.lang.String)&gt;</code><br>
        <code>&lt;java.io.File: boolean createNewFile()&gt;</code>
      </td>
    </tr>
    <tr>
      <td>Delete a file or directory</td>
      <td>
        <code>&lt;java.io.File: boolean delete()&gt;</code>
      </td>
    </tr>
    <tr>
      <td>Retrieve file or directory information</td>
      <td>
        <code>&lt;java.io.File: boolean exists()&gt;</code><br>
        <code>&lt;java.io.File: java.io.File[] listFiles()&gt;</code><br>
        <code>&lt;java.io.File: java.lang.String[] list()&gt;</code><br>
        <code>&lt;java.io.File: java.lang.String getName()&gt;</code>
      </td>
    </tr>
    <tr>
      <td>Close a file or stream</td>
      <td>
        <code>&lt;java.io.BufferedWriter: void close()&gt;</code><br>
        <code>&lt;java.io.FileOutputStream: void close()&gt;</code>
      </td>
    </tr>

    <tr>
      <td rowspan="4">Command Execution</td>
      <td>Execute the specified command as a separate process</td>
      <td>
        <code>&lt;java.lang.Runtime: java.lang.Runtime getRuntime()&gt;</code><br>
        <code>&lt;java.lang.Runtime: java.lang.Process exec(java.lang.String)&gt;</code><br>
        <code>&lt;java.lang.Runtime: java.lang.Process exec(java.lang.String,java.lang.String[])&gt;</code><br>
        <code>&lt;java.lang.Runtime: java.lang.Process exec(java.lang.String,java.lang.String[],java.io.File)&gt;</code><br>
        <code>&lt;java.lang.Runtime: java.lang.Process exec(java.lang.String[])&gt;</code><br>
        <code>&lt;java.lang.Runtime: java.lang.Process exec(java.lang.String[],java.lang.String[])&gt;</code><br>
        <code>&lt;java.lang.Runtime: java.lang.Process exec(java.lang.String[],java.lang.String[],java.io.File)&gt;</code>
      </td>
    </tr>
    <tr>
      <td>Create a new process builder</td>
      <td>
        <code>&lt;java.lang.ProcessBuilder: void &lt;init&gt;()&gt;</code><br>
        <code>&lt;java.lang.ProcessBuilder: void &lt;init&gt;(java.lang.List&lt;java.lang.String&gt;)&gt;</code><br>
        <code>&lt;java.lang.ProcessBuilder: void &lt;init&gt;(java.lang.String[])&gt;</code>
      </td>
    </tr>
    <tr>
      <td>Spawn a new process</td>
      <td>
        <code>&lt;java.lang.ProcessBuilder: java.lang.Process start()&gt;</code>
      </td>
    </tr>
    <tr>
      <td>Load dynamic library</td>
      <td>
        <code>&lt;java.lang.System: void load(java.lang.String)&gt;</code><br>
        <code>&lt;java.lang.System: void loadLibrary(java.lang.String)&gt;</code>
      </td>
    </tr>

    <tr>
      <td rowspan="3">Script Evaluation</td>
      <td>Create a new script parser</td>
      <td>
        <code>&lt;javax.script.ScriptEngineManager: void &lt;init&gt;()&gt;</code><br>
        <code>&lt;javax.script.ScriptEngineManager: javax.script.ScriptEngine getEngineByName(java.lang.String)&gt;</code><br>
        <code>&lt;org.springframework.expression.spel.standard.SpelExpressionParser: void &lt;init&gt;()&gt;</code><br>
        <code>&lt;org.springframework.expression.spel.standard.SpelExpressionParser: void &lt;init&gt;(org.springframework.expression.spel.SpelParserConfiguration)&gt;</code>
      </td>
    </tr>
    <tr>
      <td>Parse an expression</td>
      <td>
        <code>&lt;org.springframework.expression.spel.standard.SpelExpressionParser: org.springframework.expression.spel.standard.SpelExpression parseRaw(java.lang.String)&gt;</code><br>
        <code>&lt;org.springframework.expression.spel.standard.SpelExpressionParser: org.springframework.expression.spel.standard.SpelExpression doParseExpression(java.lang.String,org.springframework.expression.ParserContext)&gt;</code><br>
        <code>&lt;org.springframework.expression.spel.standard.SpelExpressionParser: org.springframework.expression.Expression doParseExpression(java.lang.String,org.springframework.expression.ParserContext)&gt;</code>
      </td>
    </tr>
    <tr>
      <td>Evaluate a script</td>
      <td>
        <code>&lt;groovy.lang.GroovyShell: java.lang.Object evaluate(java.lang.String)&gt;</code><br>
        <code>&lt;javax.script.ScriptEngine Object eval(java.lang.String)&gt;</code><br>
        <code>&lt;java.beans.Expression: void execute()&gt;</code><br>
        <code>&lt;java.beans.Statement: void execute()&gt;</code>
      </td>
    </tr>

    <tr>
      <td rowspan="2">Cryptography &amp; Data Encoding/Decoding</td>
      <td>Cipher the data</td>
      <td>
        <code>&lt;java.util.Base64: java.util.Base64$Encoder getUrlEncoder()&gt;</code><br>
        <code>&lt;java.util.Base64: java.util.Base64$Encoder getEncoder()&gt;</code><br>
        <code>&lt;javax.crypto.Cipher: javax.crypto.Cipher getInstance(java.lang.String)&gt;</code>
      </td>
    </tr>
    <tr>
      <td>Decipher the data</td>
      <td>
        <code>&lt;java.util.Base64: java.util.Base64$Decoder getDecoder()&gt;</code>
      </td>
    </tr>

    <tr>
      <td rowspan="7">Reflection</td>
      <td>Invoke a method</td>
      <td>
        <code>&lt;java.lang.reflect.Method: java.lang.Object invoke(java.lang.Object,java.lang.Object[])&gt;</code>
      </td>
    </tr>
    <tr>
      <td>Load and get the Class object</td>
      <td>
        <code>&lt;java.lang.ClassLoader: java.lang.Class defineClass(byte[],int,int)&gt;</code><br>
        <code>&lt;java.lang.ClassLoader: java.lang.Class defineClass(java.lang.String,byte[],int,int)&gt;</code><br>
        <code>&lt;java.lang.ClassLoader: java.lang.Class loadClass(java.lang.String)&gt;</code><br>
        <code>&lt;java.lang.ClassLoader: java.lang.Class loadClass(java.lang.String,boolean)&gt;</code><br>
        <code>&lt;java.net.URLClassLoader: java.lang.Class findClass(java.lang.String)&gt;</code><br>
        <code>&lt;java.lang.Class: java.lang.Class forName(java.lang.String)&gt;</code><br>
        <code>&lt;java.lang.Class: java.lang.Class forName(java.lang.String,boolean,java.lang.ClassLoader)&gt;</code>
      </td>
    </tr>
    <tr>
      <td>Get the Method object</td>
      <td>
        <code>&lt;java.lang.Class: java.lang.reflect.Method[] getDeclaredMethods()&gt;</code><br>
        <code>&lt;java.lang.Class: java.lang.reflect.Method getDeclaredMethod(java.lang.String,java.lang.Class[])&gt;</code><br>
        <code>&lt;java.lang.Class: java.lang.reflect.Method getMethod(java.lang.String,java.lang.Class[])&gt;</code>
      </td>
    </tr>
    <tr>
      <td>Get the field object</td>
      <td>
        <code>&lt;java.lang.Class: java.lang.reflect.Field[] getDeclaredFields()&gt;</code><br>
        <code>&lt;java.lang.Class: java.lang.reflect.Field getDeclaredField(java.lang.String)&gt;</code><br>
        <code>&lt;java.lang.Class: java.lang.reflect.Field getField(java.lang.String)&gt;</code><br>
        <code>&lt;java.lang.Class: java.lang.reflect.Field[] getFields()&gt;</code><br>
        <code>&lt;java.lang.reflect.Field: java.lang.Object get(java.lang.Object)&gt;</code>
      </td>
    </tr>
    <tr>
      <td>Get constructor</td>
      <td>
        <code>&lt;java.lang.Class: java.lang.reflect.Constructor getConstructor(java.lang.Class[])&gt;</code><br>
        <code>&lt;java.lang.reflect.Constructor: java.lang.Class[] getParameterTypes()&gt;</code>
      </td>
    </tr>
    <tr>
      <td>Create a new instance</td>
      <td>
        <code>&lt;java.lang.Class: java.lang.Object newInstance()&gt;</code><br>
        <code>&lt;java.lang.reflect.Constructor: java.lang.Object newInstance(java.lang.Object[])&gt;</code><br>
        <code>&lt;java.net.URLClassLoader: java.net.URLClassLoader newInstance(java.net.URL[],java.lang.ClassLoader)&gt;</code><br>
        <code>&lt;java.net.URLClassLoader: java.net.URLClassLoader newInstance(java.net.URL[])&gt;</code>
      </td>
    </tr>
    <tr>
      <td>Initial a new classloader</td>
      <td>
        <code>&lt;java.lang.Class: java.lang.ClassLoader getClassLoader()&gt;</code><br>
        <code>&lt;java.net.URLClassLoader: void &lt;init&gt;(java.net.URL[],java.lang.ClassLoader)&gt;</code><br>
        <code>&lt;java.net.URLClassLoader: void &lt;init&gt;(java.net.URL[])&gt;</code>
      </td>
    </tr>
  </tbody>
</table>

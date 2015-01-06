package com.goyoung.crypto.pki.timestamp.authenticode.servlet;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;

/**
 * Servlet implementation class TimeStampServlet
 */
@WebServlet("/timestamp.dll")
public class TimeStampServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;

	/**
	 * @see HttpServlet#HttpServlet()
	 */
	public TimeStampServlet() {
		super();
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	@Override
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		response.setContentType("text/html");
		PrintWriter out = response.getWriter();
		out.println("<!DOCTYPE html><html xmlns=\"http://www.w3.org/1999/xhtml\"><head><title>Timestamp signer</title></head>\n"+
		"<body style=\"background-color:lightgrey; font:xx-large\"><p>Gordon&#39;s simple timestamp server.\n"+
		"<br />This server responds to TimeStampRequests with a test timestamp response signer.</p>\n"+
		"</body></html>");
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	@Override
	protected void doPost(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		
		//get the real path to the WEB-INF directory for loading of deployed files:
		String webpath = request.getSession().getServletContext().getRealPath("/WEB-INF");

		// setup mime-type, request reader, and response stream
		response.setContentType("application/timestamp-reply");
		// handle plain HTTP Get requests: //PrintWriter out =
		// response.getWriter();
		ServletOutputStream os = response.getOutputStream();

		// read PostData Base64 into string buffer:
		StringBuffer sb = new StringBuffer();
		String line = null;
		try {
			BufferedReader reader = request.getReader();
			while ((line = reader.readLine()) != null)
				sb.append(line);
		} catch (Exception e) { /* report an error */
		}

		//get the TimeStampRequest PostData and strip the last byte off..
		String postData = sb.toString();
		postData = postData.substring(0, postData.length() - 1);
		
		//submit the TimeStampRequest and get the TimeStampResonse:
		byte[] signedbytes = {};
		
				try {
					signedbytes = GenTimeStamp.Generate(webpath, postData);
				} catch (UnrecoverableKeyException | OperatorCreationException
						| KeyStoreException | NoSuchProviderException
						| NoSuchAlgorithmException | CertificateException
						| CMSException e) {
					e.printStackTrace();
				}
				
		os.write(signedbytes);
		os.close();
	}
}

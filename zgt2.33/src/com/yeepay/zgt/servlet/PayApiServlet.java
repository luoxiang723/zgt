package com.yeepay.zgt.servlet;

import java.util.Map;
import java.util.HashMap;
import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.yeepay.zgt.utils.ZGTUtils;

/**
 * @author: yingjie.wang    
 * @since : 2015-09-30 20:35
 */

public class PayApiServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
       
    public PayApiServlet() {
        super();
    }

	public String formatStr(String text) {
		return text == null ? "" : text.trim();
	}
	
	//get请求
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		doPost(request, response);
	}

	//post请求
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
		//UTF-8编码
		request.setCharacterEncoding("UTF-8");
		response.setCharacterEncoding("UTF-8");
		response.setContentType("text/html");
		PrintWriter out	= response.getWriter();

		//获取各个请求参数
		String requestid			= formatStr(request.getParameter("requestid"));	
    	String amount				= formatStr(request.getParameter("amount"));
    	String assure				= formatStr(request.getParameter("assure"));
    	String productname			= formatStr(request.getParameter("productname"));
    	String productcat			= formatStr(request.getParameter("productcat"));
    	String productdesc			= formatStr(request.getParameter("productdesc"));
    	String divideinfo			= formatStr(request.getParameter("divideinfo"));
    	String callbackurl			= formatStr(request.getParameter("callbackurl"));
    	String webcallbackurl		= formatStr(request.getParameter("webcallbackurl"));
    	String bankid				= formatStr(request.getParameter("bankid"));
    	String period				= formatStr(request.getParameter("period"));
    	String memo		  			= formatStr(request.getParameter("memo"));
    	String payproducttype		= formatStr(request.getParameter("payproducttype"));
    	String userno	  			= formatStr(request.getParameter("userno"));
    	String isbind	  			= formatStr(request.getParameter("isbind"));
    	String bindid	  			= formatStr(request.getParameter("bindid"));
    	String ip		  			= formatStr(request.getParameter("ip"));
    	String cardname		  		= formatStr(request.getParameter("cardname"));
    	String idcard		  		= formatStr(request.getParameter("idcard"));
    	String bankcardnum			= formatStr(request.getParameter("bankcardnum"));
    	String mobilephone		  	= formatStr(request.getParameter("mobilephone"));
    	String cvv2		  			= formatStr(request.getParameter("cvv2"));
    	String expiredate		  	= formatStr(request.getParameter("expiredate"));
    	String mcc		  			= formatStr(request.getParameter("mcc"));
    	String areacode		  		= formatStr(request.getParameter("areacode"));
    	String ledgerno  			= formatStr(request.getParameter("ledgerno"));

		Map<String, String> params	= new HashMap<String, String>();
		params.put("requestid", 	requestid);
		params.put("amount", 		amount);
		params.put("assure", 		assure);
		params.put("productname", 	productname);
		params.put("productcat", 	productcat);
		params.put("productdesc", 	productdesc);
		params.put("divideinfo", 	divideinfo);
		params.put("callbackurl", 	callbackurl);
		params.put("webcallbackurl", webcallbackurl);
		params.put("bankid",		bankid);
		params.put("period", 		period);
		params.put("memo", 			memo);
		params.put("payproducttype", payproducttype);
		params.put("userno", 		userno);
		params.put("isbind", 		isbind);
		params.put("bindid", 		bindid);
		params.put("ip", 			ip);
		params.put("cardname", 		cardname);
		params.put("idcard", 		idcard);
		params.put("bankcardnum", 	bankcardnum);
		params.put("mobilephone", 	mobilephone);
		params.put("cvv2", 			cvv2);
		params.put("expiredate", 	expiredate);
		params.put("mcc", 			mcc);
		params.put("areacode", 		areacode);
		params.put("ledgerno", 		ledgerno);

		//第一步 生成密文data
		String data			= ZGTUtils.buildData(params, ZGTUtils.PAYAPI_REQUEST_HMAC_ORDER);
		
		//第二步 发起请求
		String requestUrl	= ZGTUtils.getRequestUrl(ZGTUtils.PAYAPI_NAME);
		Map<String, String> responseMap	= ZGTUtils.httpPost(requestUrl, data);
		
		System.out.println(requestUrl + "?customernumber=" + ZGTUtils.getCustomernumber() + "&data=" + data);
		
		//第三步 判断请求是否成功，
		if(responseMap.containsKey("code")) {
			out.println(responseMap);
			return;
		}

		//第四步 解密同步响应密文data，获取明文参数
		String responseData	= responseMap.get("data");
		Map<String, String> responseDataMap	= ZGTUtils.decryptData(responseData);
		
		System.out.println("易宝的同步响应：" + responseMap);
		System.out.println("data解密后明文：" + responseDataMap);
		
		//第五步 code=1时，方表示接口处理成功
		if(!"1".equals(responseDataMap.get("code"))) {
			out.println("code = " + responseDataMap.get("code") + "<br>");
			out.println("msg  = " + responseDataMap.get("msg"));
			return;
		}
		
		//第六步 hmac签名验证
		if(!ZGTUtils.checkHmac(responseDataMap, ZGTUtils.PAYAPI_RESPONSE_HMAC_ORDER)) {
			out.println("<br>hmac check error!<br>");
			return;
		}
		
		//第七步 进行业务处理
		//payapi支付接口，当支付方式为SALES-网银、或ONEKEY-手机一键时，需要跳转到易宝的收银台页面完成支付
		if(payproducttype.equals("SALES") || payproducttype.equals("ONEKEY")) {
			String payurl	= responseDataMap.get("payurl");
			response.sendRedirect(payurl);
		} else {
			//DIRECT无卡直连，当为发送短信验证码模式时，必须调用4.5短信验证码发送接口、4.6短信验证码确认接口才能完成支付。
			//DIRECT无卡直连，当为不发送短信验证码模式时，返回code=1，则表示扣款成功。
			//LEDGER账户支付，返回code=1，则表示扣款成功。
			//System.out.println(responseDataMap);
			request.setAttribute("responseDataMap", responseDataMap);
			RequestDispatcher view	= request.getRequestDispatcher("jsp/44payApiResponse.jsp");
			view.forward(request, response);
		}
	}
}

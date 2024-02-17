package com.zhifei.shiro.filter;

import com.zhifei.plugin.exception.entity.R;
import com.zhifei.plugin.exception.enums.RCode;
import com.zhifei.plugin.exception.exception.CustomException;
import com.zhifei.shiro.token.JwtToken;
import com.zhifei.tools.HttpTools;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.web.filter.authc.AuthenticationFilter;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class JwtFilter extends AuthenticationFilter {

    /**
     * 访问拒绝后的处理
      */
    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        HttpTools.writeJson(response, R.fail().rCode(RCode.NEED_LOGIN));
        return false;
    }

    /**
     * 访问认证处理
     * @param request
     * @param response
     * @param mappedValue
     * @return
     */
    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        try {
            // 获取Authorization请求头，并校验格式
            String auth = HttpTools.getRequest().getHeader("Authorization");
            if (StringUtils.isBlank(auth)) {
                throw new CustomException(RCode.NEED_LOGIN);
            }
            String token = auth.replaceAll("^(Bearer|bearer)", "").trim();
            if (StringUtils.isBlank(token)) {
                throw new CustomException(RCode.NEED_LOGIN);
            }

            // 生成JwtToken，交给Realm去做认证、鉴权处理
            JwtToken jwtToken = new JwtToken(token);
            getSubject(request, response).login(jwtToken);

            // 如果没有抛出异常则代表登入成功，返回true
            return true;
        } catch (Exception e) {
            R r = null;
            if (e instanceof CustomException) {
                CustomException ce = (CustomException) e;
                r = R.fail().code(ce.getCode()).message(ce.getMessage());
            } else if (e.getCause() instanceof CustomException) {
                CustomException ce = (CustomException) e.getCause();
                r = R.fail().code(ce.getCode()).message(ce.getMessage());
            } else {
                r = R.fail().message(e.getMessage());
            }
            HttpTools.writeJson(response, r);
        }
        return false;
    }

//    /**
//     * 对跨域提供支持
//     */
//    @Override
//    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
//        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
//        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
//        httpServletResponse.setHeader("Access-control-Allow-Origin", httpServletRequest.getHeader("Origin"));
//        httpServletResponse.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS,PUT,DELETE");
//        httpServletResponse.setHeader("Access-Control-Allow-Headers", httpServletRequest.getHeader("Access-Control-Request-Headers"));
//        // 跨域时会首先发送一个option请求，这里我们给option请求直接返回正常状态
//        if (httpServletRequest.getMethod().equals(RequestMethod.OPTIONS.name())) {
//            httpServletResponse.setStatus(HttpStatus.OK.value());
//            return false;
//        }
//        return super.preHandle(request, response);
//    }
}

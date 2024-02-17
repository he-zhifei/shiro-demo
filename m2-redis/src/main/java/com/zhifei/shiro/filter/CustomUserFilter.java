package com.zhifei.shiro.filter;

import com.zhifei.plugin.exception.entity.R;
import com.zhifei.plugin.exception.enums.RCode;
import com.zhifei.tools.HttpTools;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * 在FormAuthenticationFilter基础上，自定义filter，避免未登录重定向到登录页面，适合前后端分离项目
 *
 * @author He Zhifei
 * @date 2023/10/9 18:30
 */
public class CustomUserFilter extends FormAuthenticationFilter {
    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        HttpTools.writeJson(response, R.fail().rCode(RCode.NEED_LOGIN));
        return false;
    }
}

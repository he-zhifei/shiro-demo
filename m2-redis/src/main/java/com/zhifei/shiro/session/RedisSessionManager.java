package com.zhifei.shiro.session;

import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.UnknownSessionException;
import org.apache.shiro.session.mgt.SessionKey;
import org.apache.shiro.web.servlet.ShiroHttpServletRequest;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.apache.shiro.web.session.mgt.WebSessionKey;
import org.apache.shiro.web.util.WebUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.Serializable;

/**
 * 自定义session管理
 */
public class RedisSessionManager extends DefaultWebSessionManager {

    private static final String AUTHORIZATION = "Authorization";

    private static final String REFERENCED_SESSION_ID_SOURCE = "Stateless request";

    /**
     * 从请求头获取sessionId或从cookie获取
     *
     * @param request
     * @param response
     * @return
     */
    @Override
    protected Serializable getSessionId(ServletRequest request, ServletResponse response) {
        String id = WebUtils.toHttp(request).getHeader(AUTHORIZATION);
        // 如果请求头中有 Authorization 则其值为sessionId
        if (!StringUtils.isEmpty(id)) {
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_SOURCE, REFERENCED_SESSION_ID_SOURCE);
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID, id);
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_IS_VALID, Boolean.TRUE);
            return id;
        } else {
            // 否则按默认规则从cookie取sessionId
            return super.getSessionId(request, response);
        }
    }

    /**
     * 实现一次请求只从redis读取一次数据，避免一次请求多次从redis获取数据的问题，
     * 先从request获取-->redis获取-->存放在request-->返回
     *
     * @param sessionKey
     * @return
     * @throws UnknownSessionException
     */
    @Override
    protected Session retrieveSession(SessionKey sessionKey) throws UnknownSessionException {
        Serializable sessionId = this.getSessionId(sessionKey);
        ServletRequest request = sessionKey instanceof WebSessionKey ? ((WebSessionKey) sessionKey).getServletRequest() : null;
        Session session = null;
        if (check(request, sessionId)) {
            session =  (Session) request.getAttribute(sessionId.toString());
            if (session != null) return session;
        }
        session =  super.retrieveSession(sessionKey);
        if (check(request, sessionId)) {
            request.setAttribute(sessionId.toString(), session);
        }
        return session;
    }

    private Boolean check(ServletRequest request, Serializable sessionId) {
        if (request != null && sessionId != null) {
            return true;
        }
        return false;
    }
}


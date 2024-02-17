package com.zhifei.shiro.session;

import org.apache.shiro.session.Session;
import org.apache.shiro.session.UnknownSessionException;
import org.apache.shiro.session.mgt.eis.AbstractSessionDAO;
import org.springframework.data.redis.core.RedisTemplate;

import javax.annotation.Resource;
import java.io.Serializable;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * 使用缓存来管理shiro session，重写SessionDao，然后注入到DefaultWebSessionManager，再把这个manager注入到securityManager中
 */
public class RedisSessionDao extends AbstractSessionDAO {

    @Resource(name = "objectRedisTemplate")
    private RedisTemplate redisTemplate;

    /**
     * Redis中shiro session前缀
     */
    private static final String SHIRO_SESSION_ID = "shiro-session-id:";

    /**
     * Redis中shiro session过期时间（秒）
     */
    private static final int SESSION_EXPIRE_TIME = 1800;

    private String getKey(String sessionId) {
        return SHIRO_SESSION_ID + sessionId;
    }

    private void storeSession(Session session) {
        if (!legalCheck(session)) return;
        redisTemplate.opsForValue().set(getKey(session.getId().toString()),
                session, SESSION_EXPIRE_TIME, TimeUnit.SECONDS);
    }

    private Boolean legalCheck(Session session) {
        if (session == null || session.getId() == null) {
            return false;
        }
        return true;
    }

    @Override
    protected Serializable doCreate(Session session) {
        Serializable sessionId = this.generateSessionId(session);
        this.assignSessionId(session, sessionId);   //将生成的 sessionId与session捆绑
        this.storeSession(session);
        return sessionId;
    }

    @Override
    protected Session doReadSession(Serializable serializable) {
        if (serializable == null) return null;
        return (Session) redisTemplate.opsForValue().get(getKey(serializable.toString()));
    }

    @Override
    public void update(Session session) throws UnknownSessionException {
        this.storeSession(session);
    }

    @Override
    public void delete(Session session) {
        if (!legalCheck(session)) return;
        redisTemplate.delete(getKey(session.getId().toString()));
    }

    @Override
    public Collection<Session> getActiveSessions() {
        Set keys = redisTemplate.keys(getKey("*"));
        Set<Session> sessions = new HashSet<Session>();
        List values = redisTemplate.opsForValue().multiGet(keys);
        Optional.ofNullable(values).orElse(Collections.emptyList()).parallelStream().forEach(value -> {
            sessions.add((Session) value);
        });
        return sessions;
    }
}

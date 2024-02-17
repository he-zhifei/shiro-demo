package com.zhifei.shiro.test;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.subject.Subject;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SimpleAccountRealmTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(SimpleAccountRealmTest.class);

    private SimpleAccountRealm simpleAccountRealm;

    @Before
    public void startup() {
        simpleAccountRealm = new SimpleAccountRealm();
        simpleAccountRealm.addAccount("Tom", "123", "admin");
    }

    /**
     * securityManager.authenticate()-->authenticator.authenticate()-->realm
     */
    @Test
    public void test() {
        // 1.构建SecurityManager环境
        DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
        defaultSecurityManager.setRealm(simpleAccountRealm);

        // 2.主体提交用户信息
        SecurityUtils.setSecurityManager(defaultSecurityManager);
        Subject subject = SecurityUtils.getSubject();

        UsernamePasswordToken token = new UsernamePasswordToken("Tom", "123");
        subject.login(token);

        LOGGER.info("Authentication result: {}", subject.isAuthenticated());
        subject.checkRole("admin");
    }

}

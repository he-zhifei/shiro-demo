package com.zhifei.shiro.test;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.subject.Subject;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 测试IniRealm
 */
public class IniRealmTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(IniRealmTest.class);

    private static final IniRealm INI_REALM = new IniRealm("classpath:user.ini");

    @Test
    public void testIniRealm() {
        DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
        defaultSecurityManager.setRealm(INI_REALM);

        SecurityUtils.setSecurityManager(defaultSecurityManager);
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("Cherry", "111");
        subject.login(token);

        LOGGER.info("Authenticated result is: {}", subject.isAuthenticated());
        subject.checkRole("admin");
        subject.checkPermissions("user:add", "user:delete", "user:update", "user:select");

    }
}

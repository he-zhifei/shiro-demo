package com.zhifei.shiro.test;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.subject.Subject;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 测试自定义Realm：CustomizingRealm
 */
public class CustomizingRealmTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(CustomizingRealmTest.class);

    private static final CustomizingRealm CUSTOMIZING_REALM = new CustomizingRealm();

    static {
        //设置加密: md5+盐
        HashedCredentialsMatcher hashedCredentialsMatcher = new HashedCredentialsMatcher();
        hashedCredentialsMatcher.setHashAlgorithmName("md5");
        hashedCredentialsMatcher.setHashIterations(1);
        CUSTOMIZING_REALM.setCredentialsMatcher(hashedCredentialsMatcher);
    }

    @Test
    public void testCustomizingRealm() {
        DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
        defaultSecurityManager.setRealm(CUSTOMIZING_REALM);

        SecurityUtils.setSecurityManager(defaultSecurityManager);
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("Jay", "222");
        subject.login(token);

        LOGGER.info("\r\n##################\r\nAuthenticated result is: " + subject.isAuthenticated() + "\r\n##################");
        subject.checkPermissions("admin:add", "admin:delete", "user:add", "user:delete");

        subject.logout();
        LOGGER.info("\r\n##################\r\nAuthenticated result is: " + subject.isAuthenticated() + "\r\n##################");
    }
}

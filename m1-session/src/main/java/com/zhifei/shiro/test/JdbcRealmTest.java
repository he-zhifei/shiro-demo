package com.zhifei.shiro.test;

import com.alibaba.druid.pool.DruidDataSource;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.jdbc.JdbcRealm;
import org.apache.shiro.subject.Subject;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 测试JdbcRealm
 */
public class JdbcRealmTest {

    private static final Logger LOGGER;

    private static final DruidDataSource DRUID_DATA_SOURCE;

    private static final JdbcRealm JDBC_REALM;

    static {
        //初始化日志
        LOGGER = LoggerFactory.getLogger(JdbcRealmTest.class);

        //初始化德鲁伊数据源
        DRUID_DATA_SOURCE = new DruidDataSource();
        DRUID_DATA_SOURCE.setUrl("jdbc:mysql://localhost:3306/shiro-demo");
        DRUID_DATA_SOURCE.setDriverClassName("com.mysql.jdbc.Driver");
        DRUID_DATA_SOURCE.setUsername("root");
        DRUID_DATA_SOURCE.setPassword("123456");

        //初始化JdbcRealm
        JDBC_REALM = new JdbcRealm();
        JDBC_REALM.setDataSource(DRUID_DATA_SOURCE);

        //使用JdbcRealm，检查权限时，需要把这个设为true
        JDBC_REALM.setPermissionsLookupEnabled(true);

        //如果需要自定义users表，user_roles表，roles_permissions表，需要重新设置它们各自的查询语句
        String customizing_users_query_sql = "select password from customizing_users where username = ?";
        JDBC_REALM.setAuthenticationQuery(customizing_users_query_sql);
    }

    @Test
    public void testJdbcRealm() {
        // 1.配置SecurityManager环境
        DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
        defaultSecurityManager.setRealm(JDBC_REALM);

        // 2.主体用户提交认证信息
        SecurityUtils.setSecurityManager(defaultSecurityManager);
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("Sam", "6666");
        subject.login(token);

        LOGGER.info("\r\n##################Authenticated result is: " + subject.isAuthenticated() + "\r\n##################");
        subject.checkRoles("admin", "user");
        subject.checkPermissions("user:add", "user:select");
    }
}

package com.zhifei.shiro.config;

import com.zhifei.shiro.filter.JwtFilter;
import com.zhifei.shiro.realm.JwtRealm;
import org.apache.shiro.mgt.DefaultSessionStorageEvaluator;
import org.apache.shiro.mgt.DefaultSubjectDAO;
import org.apache.shiro.mgt.SubjectFactory;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.mgt.DefaultWebSubjectFactory;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;

import java.util.HashMap;
import java.util.Map;

/**
 * shiro配置类（Jwt）
 */
@Configuration
public class ShiroConfig {

    @Bean
    public ShiroFilterFactoryBean shiroFilter() {
        ShiroFilterFactoryBean bean = new ShiroFilterFactoryBean();
        bean.setSecurityManager(defaultWebSecurityManager());

        // shiro默认过滤器详细：org.apache.shiro.web.filter.mgt.DefaultFilter
        Map<String, String> filterChains = new HashMap<String, String>();
        filterChains.put("/sysUser/login", "anon");
        filterChains.put("/sysUser/logout", "anon");
        filterChains.put("/sysUser/refreshToken", "anon");

        // 配置自定义JwtFilter
        JwtFilter jwtFilter = new JwtFilter();
        String filterName = jwtFilter.getClass().getSimpleName();
        bean.setFilters(new HashMap() {{put(filterName, jwtFilter);}});
        filterChains.put("/**", filterName);

        bean.setFilterChainDefinitionMap(filterChains);
        return bean;
    }

    @Bean
    public DefaultWebSecurityManager defaultWebSecurityManager() {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(jwtRealm());

        /*
         * 关闭shiro自带的session，详情见文档
         * http://shiro.apache.org/session-management.html#SessionManagement-StatelessApplications%28Sessionless%29
         */
        DefaultSubjectDAO subjectDAO = new DefaultSubjectDAO();
        DefaultSessionStorageEvaluator defaultSessionStorageEvaluator = new DefaultSessionStorageEvaluator();
        defaultSessionStorageEvaluator.setSessionStorageEnabled(false);
        subjectDAO.setSessionStorageEvaluator(defaultSessionStorageEvaluator);
        securityManager.setSubjectDAO(subjectDAO);

        // 禁用Subject的Session
        securityManager.setSubjectFactory(subjectFactory());

        return securityManager;
    }

    @Bean
    public JwtRealm jwtRealm() {
        JwtRealm realm = new JwtRealm();
//        realm.setCredentialsMatcher(hashedCredentialsMatcher());
        return realm;
    }

//    @Bean
//    public HashedCredentialsMatcher hashedCredentialsMatcher() {
//        HashedCredentialsMatcher hashedCredentialsMatcher = new HashedCredentialsMatcher();
//        hashedCredentialsMatcher.setHashAlgorithmName("md5");
////        // 需要确保这里的加密次数与数据库的保持一致，因此需要在realm认证时，动态设定
////        hashedCredentialsMatcher.setHashIterations(5);
//        return hashedCredentialsMatcher;
//    }

    @Bean
    public SubjectFactory subjectFactory() {
        return new DefaultWebSubjectFactory() {
            @Override
            public Subject createSubject(SubjectContext context) {
                // 不创建Subject的Session
                context.setSessionCreationEnabled(false);
                return super.createSubject(context);
            }
        };
    }


    /**
     * 若使用shiro的注解，则需要配置如下两个bean：lifecycleBeanPostProcessor，authorizationAttributeSourceAdvisor
     */

    @Bean
    @DependsOn("lifecycleBeanPostProcessor")
    public DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator() {
        DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator = new DefaultAdvisorAutoProxyCreator();
        defaultAdvisorAutoProxyCreator.setProxyTargetClass(true);
        return defaultAdvisorAutoProxyCreator;
    }

    @Bean
    public LifecycleBeanPostProcessor lifecycleBeanPostProcessor() {
        return new LifecycleBeanPostProcessor();
    }

    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor() {
        AuthorizationAttributeSourceAdvisor advisor = new AuthorizationAttributeSourceAdvisor();
        advisor.setSecurityManager(defaultWebSecurityManager());
        return advisor;
    }
}

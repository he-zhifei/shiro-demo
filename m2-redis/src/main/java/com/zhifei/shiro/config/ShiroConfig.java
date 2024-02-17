package com.zhifei.shiro.config;

import com.zhifei.shiro.cache.RedisCacheManager;
import com.zhifei.shiro.filter.CustomUserFilter;
import com.zhifei.shiro.realm.RedisRealm;
import com.zhifei.shiro.session.RedisSessionDao;
import com.zhifei.shiro.session.RedisSessionManager;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

/**
 * shiro配置类
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

//        filterChains.put("/**", "authc");
        CustomUserFilter customUserFilter = new CustomUserFilter();
        String filterName = customUserFilter.getClass().getSimpleName();
        bean.setFilters(new HashMap() {{put(filterName, customUserFilter);}});
        filterChains.put("/**", filterName);

        bean.setFilterChainDefinitionMap(filterChains);
        return bean;
    }

    @Bean
    public DefaultWebSecurityManager defaultWebSecurityManager() {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(redisRealm());
        securityManager.setRememberMeManager(cookieRememberMeManager());
        securityManager.setSessionManager(redisSessionManager());
        securityManager.setCacheManager(redisCacheManager());
        return securityManager;
    }

    @Bean
    public RedisRealm redisRealm() {
        RedisRealm realm = new RedisRealm();
        realm.setCredentialsMatcher(hashedCredentialsMatcher());
        return realm;
    }

    @Bean
    public HashedCredentialsMatcher hashedCredentialsMatcher() {
        HashedCredentialsMatcher hashedCredentialsMatcher = new HashedCredentialsMatcher();
        hashedCredentialsMatcher.setHashAlgorithmName("md5");
//        // 需要确保这里的加密次数与数据库的保持一致，因此需要在realm认证时，动态设定
//        hashedCredentialsMatcher.setHashIterations(5);
        return hashedCredentialsMatcher;
    }

    @Bean
    public CookieRememberMeManager cookieRememberMeManager() {
        CookieRememberMeManager cookieRememberMeManager = new CookieRememberMeManager();
        cookieRememberMeManager.setCookie(simpleCookie());
        /**
         * 指定cookie加密的AES密钥，不然每次生成新的密钥，导致RememberMe功能失效，报错
         * AES-128(16)、AES-192(24)、AES-256(32)
         * new String(Base64.encode("w(s0df?.1S.z~1w3e!sfw9p?1w!=2ew_".getBytes(StandardCharsets.UTF_8)));
         * 这里生成cookie加密的AES密钥为32字节
         */
        cookieRememberMeManager.setCipherKey(Base64.decode("dyhzMGRmPy4xUy56fjF3M2Uhc2Z3OXA/MXchPTJld18="));
        return cookieRememberMeManager;
    }

    @Bean
    public SimpleCookie simpleCookie() {
        SimpleCookie simpleCookie = new SimpleCookie("rememberMe");
        // 7天，单位：秒
        simpleCookie.setMaxAge(60 * 60 * 24 * 7);
        return simpleCookie;
    }

    @Bean
    public SessionManager redisSessionManager() {
        RedisSessionManager redisSessionManager = new RedisSessionManager();
        redisSessionManager.setSessionDAO(redisSessionDao());
        return redisSessionManager;
    }

    @Bean
    public RedisSessionDao redisSessionDao() {
        return new RedisSessionDao();
    }

    @Bean
    public RedisCacheManager redisCacheManager() {
        return new RedisCacheManager();
    }

    /**
     * 若使用shiro的注解，则需要配置如下两个bean：lifecycleBeanPostProcessor，authorizationAttributeSourceAdvisor
     */

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

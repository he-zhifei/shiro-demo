package com.zhifei.shiro.test;

import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

import java.util.*;

/**
 * 自定义Realm，继承AuthorizingRealm，使用map模拟数据库的数据
 */
public class CustomizingRealm extends AuthorizingRealm {

    //这里使用map模拟从数据库查到的users数据
    private Map<String, String> users = new HashMap<String, String>();

    //模拟角色表user_roles
    private Map<String, Set<String>> user_roles = new HashMap<String, Set<String>>();

    //模拟权限表roles_permissions
    private Map<String, Set<String>> roles_permissions = new HashMap<String, Set<String>>();

    //存放用户的所有权限
    private Set<String> permissions = new HashSet<String>();

    //数据初始化
    {
        users.put("Jay", "caaf680f9b9164125ac70490b83edf93");

        Set<String> roles = new HashSet<String>();
        roles.add("admin");
        roles.add("user");
        user_roles.put("Jay", roles);

        Set<String> permissions_admin = new HashSet<String>();
        permissions_admin.add("admin:add");
        permissions_admin.add("admin:delete");
        permissions_admin.add("user:add");
        roles_permissions.put("admin", permissions_admin);

        Set<String> permissions_user = new HashSet<String>();
        permissions_user.add("user:add");
        permissions_user.add("user:delete");
        roles_permissions.put("user", permissions_user);

    }

    /**
     * 认证
     * @param token
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        String username = (String) token.getPrincipal();
        String password = getPasswordByUsername(username);
        if (StringUtils.isBlank(password)) return null;
        SimpleAuthenticationInfo info = new SimpleAuthenticationInfo("Jay", password, "CustomizingRealm");
        info.setCredentialsSalt(ByteSource.Util.bytes("my_salt"));
        return info;
    }

    /**
     * 授权
     * @param principals
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        String username = (String) principals.getPrimaryPrincipal();
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        info.setStringPermissions(getPermissionsByUsername(username));
        return info;
    }

    /**
     * 根据用户名获取其密码
     * @param username
     * @return 密码
     */
    private String getPasswordByUsername(String username) {
        return users.get(username);
    }

    /**
     * 根据用户名获取其所有角色
     * @param username
     * @return 所有角色
     */
    private Set<String> getRolesByUsername(String username) {
        return user_roles.get(username);
    }

    /**
     * 根据用户名获取其所有角色的所有权限
     * @param username
     * @return 所有权限
     */
    private Set<String> getPermissionsByUsername(String username) {
        Set<String> roles = getRolesByUsername(username);
        Optional.ofNullable(roles).orElse(new HashSet<String>()).parallelStream().forEach((role) ->{
            permissions.addAll(roles_permissions.get(role));
        });
        return permissions;
    }

    public static void main(String[] args) {
        String password = "123456";
        String salt = UUID.randomUUID().toString();
        int hashIterations = new Random().nextInt(512) + 512;
        Md5Hash md5Hash = new Md5Hash(password, salt, hashIterations);
        System.out.println("password:" + password);
        System.out.println("salt:" + salt);
        System.out.println("hashIterations:" + hashIterations);
        System.out.println("密文：" + md5Hash.toString());
    }
}

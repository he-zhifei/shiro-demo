package com.zhifei.shiro.realm;

import com.zhifei.entity.SysMenu;
import com.zhifei.entity.SysRole;
import com.zhifei.entity.SysUser;
import com.zhifei.plugin.exception.enums.RCode;
import com.zhifei.plugin.exception.exception.CustomException;
import com.zhifei.service.SysUserService;
import com.zhifei.vo.RolesAndMenus;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

/**
 * 自定义的Realm
 */
public class CustomRealm extends AuthorizingRealm {

    @Autowired
    private SysUserService sysUserService;

    @Autowired
    private HashedCredentialsMatcher hashedCredentialsMatcher;

    /**
     * 认证
     *
     * @param token
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        String username = (String) token.getPrincipal();
        SysUser user = sysUserService.getByUsername(username);
        checkSysUser(user);
        // 动态设置加盐加密的hash次数
        hashedCredentialsMatcher.setHashIterations(user.getHashIterations());
        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(user.getUsername(), user.getPassword(),
                ByteSource.Util.bytes(user.getSalt()), getName());
        return authenticationInfo;
    }

    /**
     * 授权
     *
     * @param principals
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        String username = (String) principals.getPrimaryPrincipal();
        SysUser user = sysUserService.getByUsername(username);
        checkSysUser(user);

        // 获取用户实际上的角色和菜单权限
        RolesAndMenus rolesAndMenus = sysUserService.getRealRolesAndMenus(user.getId());
        Set<String> roles = new HashSet<String>();
        Set<String> permissions = new HashSet<String>();
        Set<SysRole> roleSet = rolesAndMenus.getRoleSet();
        Set<SysMenu> menuSet = rolesAndMenus.getMenuSet();
        Optional.ofNullable(roleSet).orElse(Collections.emptySet()).forEach(role -> {
            roles.add(role.getName());
        });
        Optional.ofNullable(menuSet).orElse(Collections.emptySet()).forEach(menu -> {
            permissions.add(menu.getPermission());
        });

        authorizationInfo.setRoles(roles);
        authorizationInfo.setStringPermissions(permissions);
        return authorizationInfo;
    }

    /**
     * 检查用户是否存在且可用
     * @param user
     */
    private void checkSysUser(SysUser user) {
        if (user == null) {
            throw new CustomException(RCode.INCORRECT_PRINCIPAL);
        }
        if (user.getEnabled() == 0) {
            throw new CustomException(RCode.ACCOUNT_LOCKED);
        }
    }

}

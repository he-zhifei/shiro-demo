package com.zhifei.shiro.realm;

import com.zhifei.entity.SysMenu;
import com.zhifei.entity.SysRole;
import com.zhifei.entity.SysUser;
import com.zhifei.plugin.exception.enums.RCode;
import com.zhifei.plugin.exception.exception.CustomException;
import com.zhifei.service.SysUserService;
import com.zhifei.shiro.properties.JwtRsaProperties;
import com.zhifei.shiro.token.JwtToken;
import com.zhifei.tools.jwt.JwtTools;
import com.zhifei.vo.RolesAndMenus;
import com.zhifei.vo.UserVo;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

/**
 * 自定义的Realm（Jwt）
 */
public class JwtRealm extends AuthorizingRealm {

    @Autowired
    private JwtRsaProperties jwtRsaProps;

    @Autowired
    private SysUserService sysUserService;

    /**
     * 只支持对JwtToken的认证、鉴权
     * @param token
     * @return
     */
    @Override
    public boolean supports(AuthenticationToken token) {
        return token != null && token instanceof JwtToken;
    }

    /**
     * 认证
     * @param token
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) {
        JwtToken jwtToken = (JwtToken) token;
        String jwt = jwtToken.getToken();

        // 校验签名是否合法
        if (!JwtTools.signer(jwtRsaProps.getPrivateKey()).verifyJwt(jwt)) {
            throw new CustomException(RCode.NEED_LOGIN);
        }

        // 获取jwt中的用户名
        UserVo userVo = JwtTools.parser(jwtRsaProps.getPublicKey()).parseJwt4Data(jwt, UserVo.class);

        // 校验用户是否真实存在，且处于可用状态
        String username = userVo.getUsername();
        SysUser user = sysUserService.getByUsername(username);
        checkSysUser(user);

        return new SimpleAuthenticationInfo(username, jwt, getClass().getName());
    }

    /**
     * 授权
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

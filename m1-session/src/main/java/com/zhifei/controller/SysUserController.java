package com.zhifei.controller;

import com.zhifei.entity.SysUser;
import com.zhifei.plugin.exception.annotation.GlobalException;
import com.zhifei.plugin.exception.entity.R;
import com.zhifei.service.SysUserService;
import com.zhifei.vo.RolesAndMenus;
import com.zhifei.vo.UserVo;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.SecurityUtils;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@GlobalException
@Validated
@RestController
@RequestMapping("/sysUser")
public class SysUserController {

    @Autowired
    private SysUserService sysUserService;

    /**
     * 登录，同时，在注册时，要把加密盐和hash次数保存到数据库
     * @param sysUser
     * @return
     */
    @PostMapping("/login")
    public R login(@RequestBody @Validated SysUser sysUser) {
        SysUser user = sysUserService.login(sysUser);
        UserVo userVo = new UserVo();
        BeanUtils.copyProperties(user, userVo);

        // 设置token、角色、菜单路由、菜单权限
        userVo.setToken(String.valueOf(SecurityUtils.getSubject().getSession().getId()));
        RolesAndMenus rolesAndMenus = sysUserService.getRealRolesAndMenus(user.getId());
        Set<String> roles = new HashSet<String>();
        Optional.ofNullable(rolesAndMenus.getRoleSet()).orElse(Collections.emptySet()).forEach(role -> {
            roles.add(role.getName());
        });
        userVo.setRoles(roles);
        Set<String> routers = new HashSet<String>();
        Set<String> permissions = new HashSet<String>();
        Optional.ofNullable(rolesAndMenus.getMenuSet()).orElse(Collections.emptySet()).forEach(menu -> {
            String menuName = menu.getName();
            if (StringUtils.isNotBlank(menuName)) {
                routers.add(menuName);
            }
            permissions.add(menu.getPermission());
        });
        userVo.setRouters(routers);
        userVo.setPermissions(permissions);

        return R.success().data(userVo);
    }

    /**
     * 退出登录
     * @return
     */
    @GetMapping("/logout")
    public R logout() {
        SecurityUtils.getSubject().logout();
        return R.success().message("已退出登录");
    }

}

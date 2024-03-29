package com.zhifei.service.impl;

import com.zhifei.dao.SysUserMapper;
import com.zhifei.entity.SysMenu;
import com.zhifei.entity.SysRole;
import com.zhifei.entity.SysUser;
import com.zhifei.plugin.exception.exception.CustomException;
import com.zhifei.service.SysUserService;
import com.zhifei.vo.RolesAndMenus;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
public class SysUserServiceImpl implements SysUserService {

    @Autowired
    private SysUserMapper sysUserMapper;

    @Override
    public SysUser getByUsername(String username) {
        return sysUserMapper.getByUsername(username);
    }

    @Override
    public List<SysRole> getRolesByUserId(Long id) {
        return sysUserMapper.getRolesByUserId(id);
    }

    @Override
    public List<SysMenu> getMenusByUserId(Long id) {
        return sysUserMapper.getMenusByUserId(id);
    }

    @Override
    public SysUser login(SysUser sysUser) {
        UsernamePasswordToken token = new UsernamePasswordToken(sysUser.getUsername(), sysUser.getPassword(), true);
        Subject subject = SecurityUtils.getSubject();
        try {
            subject.login(token);
        } catch (Exception e) {
            if (e != null && e.getCause() instanceof CustomException) {
                throw (CustomException) e.getCause();
            } else {
                throw e;
            }
        }
        SysUser user = getByUsername(sysUser.getUsername());
        return user;
    }

    @Override
    public List<SysRole>  getLowerLevelRoles(int level) {
        return sysUserMapper.getLowerLevelRoles(level);
    }

    @Override
    public List<SysMenu> getLowerLevelMenus(int level) {
        return sysUserMapper.getLowerLevelMenus(level);
    }

    @Override
    public RolesAndMenus getRealRolesAndMenus(Long userId) {
        // 先查找属于当前用户的角色和权限
        List<SysRole> roles = getRolesByUserId(userId);
        List<SysMenu> menus = getMenusByUserId(userId);

        // 记录当前用户所有角色中的最高级别
        int topLevel = 1;
        if (roles != null && roles.size() > 0) {
            for (int i = 0, size = roles.size(); i < size; i++) {
                topLevel = Math.max(topLevel, roles.get(i).getLevel());
            }
        }

        // 再查找比当前用户所有角色最高级别低的角色和权限（高级别的角色包含自身的权限和低级别的所有角色权限）
        List<SysRole> lowerLevelRoles = getLowerLevelRoles(topLevel);
        List<SysMenu> lowerLevelMenus = getLowerLevelMenus(topLevel);

        // 已经重写了SysRole、SysMenu的equals和hashCode方法，添加到Set中自动去重
        Set<SysRole> roleSet = new HashSet<SysRole>();
        Set<SysMenu> menuSet = new HashSet<SysMenu>();
        roleSet.addAll(roles);
        roleSet.addAll(lowerLevelRoles);
        menuSet.addAll(menus);
        menuSet.addAll(lowerLevelMenus);

        RolesAndMenus rolesAndMenus = new RolesAndMenus();
        rolesAndMenus.setRoleSet(roleSet);
        rolesAndMenus.setMenuSet(menuSet);
        return rolesAndMenus;
    }

}

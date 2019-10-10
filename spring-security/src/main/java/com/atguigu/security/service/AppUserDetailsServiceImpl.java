package com.atguigu.security.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * @author tanglei
 * @date 2019/9/17  19:19
 */
//用户登录时由springSecurity自动封装主体信息的  实现类
@Service
public class AppUserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    JdbcTemplate jdbcTemplate;

    //主体封装的方法
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //username:用户登录提交的账号
        //从数据库中查询
        String sql = "SELECT  id, username , loginacct , userpswd , email  FROM t_admin WHERE loginacct = ?";
        Map<String, Object> map = jdbcTemplate.queryForMap(sql, username);
        List<GrantedAuthority> authorities = new ArrayList<>();

        //如果用户信息查询成功，从数据库中查询该用户的权限角色信息
        sql = "select roleid,`name` from t_admin_role join t_role on roleid = t_role.id where adminid = ? ";
        //用户的权限集合应该包含 角色列表 + 权限列表 先查询角色列表在根据 角色列表查询权限列表
        List<Map<String, Object>> list = jdbcTemplate.queryForList(sql, map.get("id"));
        for (Map<String, Object> m : list) {
            authorities.add(new SimpleGrantedAuthority("ROLE_"+m.get("name").toString()));
        }
        sql = "select permissionid,name from t_role_permission join t_permission on permissionid=t_permission.id where roleid = ? and name is not null";

        //查询权限列表，然后将权限添加到权限集合中
        for (Map<String, Object> m : list) {
            //根据角色id查询角色列表
            List<Map<String, Object>> permissions = jdbcTemplate.queryForList(sql, m.get("roleid"));
            for (Map<String, Object> permission : permissions) {
                //将权限放入权限集合中
                authorities.add(new SimpleGrantedAuthority(permission.get("name").toString()));
            }
        }
        System.out.println(authorities);
        //封装主体对象返回[登录的账号、从数据库中查询的密码、权限集合(如果表示角色需要在前面拼接ROLE_前缀)]
        return new User(username,map.get("userpswd").toString(),authorities);
    }


}

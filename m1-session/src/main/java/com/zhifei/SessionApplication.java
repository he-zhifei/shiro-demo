package com.zhifei;

import org.apache.shiro.crypto.hash.SimpleHash;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;

import java.util.Random;
import java.util.UUID;

@SpringBootApplication(exclude = DataSourceAutoConfiguration.class)     //动态数据源需要忽略自动配置
public class SessionApplication {
    public static void main(String[] args) {
        SpringApplication.run(SessionApplication.class, args);

        // 密码生成demo
        String salt = UUID.randomUUID().toString();
        int hashIterations = (int) (Math.random()*8 + 8);    // [8, 16)
        SimpleHash hash = new SimpleHash("md5", "123456", salt, hashIterations);
        System.out.println(salt);
        System.out.println(hashIterations);
        System.out.println(hash);
    }
}

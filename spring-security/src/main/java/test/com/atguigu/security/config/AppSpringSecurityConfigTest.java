package test.com.atguigu.security.config;

import org.junit.Test; 
import org.junit.Before; 
import org.junit.BeforeClass;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 @author tanglei
*/  
public class AppSpringSecurityConfigTest { 

    @Test
    public void test(){
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        System.out.println(encoder.encode("123456"));
    }
    
} 

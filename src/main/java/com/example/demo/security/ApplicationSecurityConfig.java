package com.example.demo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.example.demo.auth.ApplicationUserService;
import com.example.demo.jwt.JwtUsernameAndPasswordAuthenticationFilter;

import static com.example.demo.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) //Apply security with annotations in controller
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter{
	
	private final PasswordEncoder passwordEncoder;
	private final ApplicationUserService applicationUserService;
	
	@Autowired
	public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService) {
		this.passwordEncoder = passwordEncoder;
		this.applicationUserService = applicationUserService;
	}

	@Override
	//Method of configuration spring security
	protected void configure(HttpSecurity http) throws Exception {
		// TODO Auto-generated method stub
		http
			//.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
			//.and()
			.csrf().disable()
			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //configure the sessionManagment: in this session is stored on database
			.and()
			.addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager())) //configure the filter in order to allow jwt access
			.authorizeRequests()
			.antMatchers("/", "index", "/css/*", "/js/*").permitAll()
			.antMatchers("/api/**").hasRole(STUDENT.name())
			//The next antMatcher are configured by annotations with @PreAuthorize in the controller
			//.antMatchers(HttpMethod.DELETE,"/managment/api/**").hasAuthority(COURSE_WRITE.getPermission())
			//.antMatchers(HttpMethod.POST,"/managment/api/**").hasAuthority(COURSE_WRITE.getPermission())
			//.antMatchers(HttpMethod.PUT,"/managment/api/**").hasAuthority(COURSE_WRITE.getPermission())
			//.antMatchers(HttpMethod.GET, "/managment/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
			.anyRequest()
			.authenticated();
			//.and()
			//.httpBasic();
			//.formLogin() //force a login form
			//	.loginPage("/login").permitAll() //define the login webpage
			//	.permitAll()
			//	.defaultSuccessUrl("/courses", true) //reedirect to courses after login
			//	.passwordParameter("password") //Defines the name of password parameter which should have on login html form
			//	.usernameParameter("username") //Defines the name of username parameter which should have on login html form
			//.and()
			//.rememberMe() //SesionId expires after two weeks
			//	.rememberMeParameter("remember-me") //Defines the name of rememberMe parameter which should have on login html form
			//.and()
			//.logout()
			//	.logoutUrl("/logout")
			//	.logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET")) //force the logout to use GET method
			//	.clearAuthentication(true)
			//	.invalidateHttpSession(true)
			//	.deleteCookies("JSESSIONID", "remember-me")
			//	.logoutSuccessUrl("/login");
	}

	
	//Next lines show how to implements memory login: no Database is used, data is only saved in memory
	//@Override
	//@Bean
	//Method of how retrieve users from database
	//protected UserDetailsService userDetailsService() {
	//	UserDetails annaSmithUser = User.builder()
	//		.username("annasmith")
	//		.password(passwordEncoder.encode("password"))
	//		//.roles(ApplicationUserRole.STUDENT.name()) //ROLE_STUDENT
	//		.authorities(STUDENT.getGrantedAuthorities())
	//		.build();
	//	
	//	UserDetails lindaUser = User.builder()
	//		.username("linda")
	//		.password(passwordEncoder.encode("password123"))
	//		//.roles(ApplicationUserRole.ADMIN.name()) //ROLE_ADMIN
	//		.authorities(ADMIN.getGrantedAuthorities())
	//		.build();
	//	
	//	UserDetails tomUser = User.builder()
	//			.username("tom")
	//			.password(passwordEncoder.encode("password123"))
	//			//.roles(ApplicationUserRole.ADMINTRAINEE.name()) //ROLE_ADMINTRAINEE
	//			.authorities(ADMINTRAINEE.getGrantedAuthorities())
	//			.build();
	//	
	//	return new InMemoryUserDetailsManager(
	//			annaSmithUser,
	//			lindaUser,
	//			tomUser
	//	);
	//	
	//}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth)  throws Exception {
		auth.authenticationProvider(daoAuthenticationProvider());
		
	}
	
	@Bean
	public DaoAuthenticationProvider daoAuthenticationProvider() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setPasswordEncoder(passwordEncoder);
		provider.setUserDetailsService(applicationUserService);
		return provider;
	}
}

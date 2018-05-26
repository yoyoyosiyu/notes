### Spring Boot Security OAuth2 的源码研究

#### 入口 @EnableOAuth2Client

最好的JAVA开发工具还是Intellij Idea。按住ALT键，然后将鼠标移至你想查看的类型上面，会高亮显示带下划线。然后点击即可打开这个类型的类定义文件。没有源码也可以，Intellij 会帮你反编译，如果有源码，那么就会打开源码。你可以打断点调试，非常的厉害。

@EnableOAuth2Client 导入了OAuth2ClientConfiguration

OAuth2ClientConfiguration是个配置类

```java
@Configuration  
public class OAuth2ClientConfiguration {  

	@Bean  
	public OAuth2ClientContextFilter oauth2ClientContextFilter() {  
		OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();  
		return filter;  
	}  

	@Bean  
	@Scope(value = "request", proxyMode = ScopedProxyMode.INTERFACES)  
	protected AccessTokenRequest accessTokenRequest(@Value("#{request.parameterMap}")  
	Map<String, String[]> parameters, @Value("#{request.getAttribute('currentUri')}")  
	String currentUri) {  
		DefaultAccessTokenRequest request = new DefaultAccessTokenRequest(parameters);  
		request.setCurrentUri(currentUri);
		return request;  
	}  
	  
	@Configuration  
	protected static class OAuth2ClientContextConfiguration {  
	     
		@Resource  
		@Qualifier("accessTokenRequest")  
		private AccessTokenRequest accessTokenRequest;  
		@Bean  
		@Scope(value = "session", proxyMode = ScopedProxyMode.INTERFACES)  
		public OAuth2ClientContext oauth2ClientContext() {  
		   return new DefaultOAuth2ClientContext(accessTokenRequest);  
		}
	}  

}
```
这里定义了三个Bean：

- accessTokenRequest
- OAuth2ClientContext 
- OAuth2ClientContextFilter

注意accessTokenRequest和OAuth2ClientContext 的Scope定义，一个作用域是Http Requst， 一个是Http Session。他们的实际类型分别为DefaultAccessTokenRequest 和 DefaultOAuth2ClientContext，这两个Bean都使用了ScopedProxyMode.INTERFACES，这样带来的问题就是调试的时候会进入一大段Proxy的代码，没法进入实际的代码。所以，最好的办法就是进入源码打断点。还是利用ALT键，然后分别进入DefaultAccessTokenRequest和DefaultOAuth2ClientContext的源码文件，然后在你需要的地方提前打上断点。

我在DefaultAccessTokenRequest的getPreservedState和setPreservedState 以及DefaultOAuth2ClientContext的setPreservedState和removePreservedState打上断点。然后可以利用调用栈来跳到其他相关的源码位置。

为什么打在这两个地方，因为这两个地方是OAuth2Client跳入认证服务器和获取AccessToken的必经地方。

下面说说的我调试和研究代码的方法：

首先我会用最快的方法构建好一个客户端，代码很简单：

Client1Application.java
```java
@RestController  
@EnableOAuth2Sso  
@SpringBootApplication  
public class Client1Application extends WebSecurityConfigurerAdapter {  
  
	public static void main(String[] args) {  
	      SpringApplication.run(Client1Application.class, args);  
	}  
}
```
application.yml
```yaml
security:  
	oauth2: sso: login-path: /login  
	   client:  
	client-id: acme  
	     client-secret: acmesecret  
	     user-authorization-uri: http://127.0.0.1:9999/oauth/authorize  
	     access-token-uri: http://127.0.0.1:9999/oauth/token  
	     client-authentication-scheme: form  
	 resource:  
 jwt: key-uri: http://127.0.0.1:9999/oauth/token_key  
server:  
	port: 8080
```

@EnableOAuth2Sso 是spring-security-oauth2-autoconfigure定义的，用于Spring Boot的自动配置，这点要注意。有两种使用形式，他们有细微的差别。一个是用在WebSecurityConfigurerAdapter的扩展类上，一个是不用在这个类上。

用在WebSecurityConfigurerAdapter上的时候，会导入OAuth2SsoCustomConfiguration类的配置，如果不使用的话，会导入OAuth2SsoDefaultConfiguration的配置，这个可以通过下面的代码来看出来。

首先是EnableOAuth2Sso 注解的定义
```java
@Target(ElementType.TYPE)  
@Retention(RetentionPolicy.RUNTIME)  
@Documented  
@EnableOAuth2Client  
@EnableConfigurationProperties(OAuth2SsoProperties.class)  
@Import({ OAuth2SsoDefaultConfiguration.class, OAuth2SsoCustomConfiguration.class,  
  ResourceServerTokenServicesConfiguration.class })  
public @interface EnableOAuth2Sso {  
  
}
```
这里还看不出区别，我们看看OAuth2SsoDefaultConfiguration
```java
@Configuration  
@Conditional(NeedsWebSecurityCondition.class)  
public class OAuth2SsoDefaultConfiguration extends WebSecurityConfigurerAdapter {
```
和OAuth2SsoCustomConfiguration
```java
@Configuration  
@Conditional(EnableOAuth2SsoCondition.class)  
public class OAuth2SsoCustomConfiguration  
      implements ImportAware, BeanPostProcessor, ApplicationContextAware {
```
OAuth2SsoDefaultConfiguration 就扩展自WebSecurityConfigurerAdapter。
OAuth2SsoDefaultConfiguration和OAuth2SsoCustomConfiguration不会同时被导入（Import），这是由于他们的使用条件不同，@Conditional这个注解决定了这个类会被Import必需要满足的条件。我们看看OAuth2SsoDefaultConfiguration的条件注解 ```@Conditional(NeedsWebSecurityCondition.class)``` ，注解里NeedsWebSecurityCondition类定义了测试规则。
```java
protected static class NeedsWebSecurityCondition extends EnableOAuth2SsoCondition {  
  
	@Override  
	public ConditionOutcome getMatchOutcome(ConditionContext context,  
	AnnotatedTypeMetadata metadata) {  
	    return ConditionOutcome.inverse(super.getMatchOutcome(context, metadata));  
	}  
}
```
NeedsWebSecurityCondition扩展自EnableOAuth2SsoCondition， 而EnableOAuth2SsoCondition正是OAuth2SsoCustomConfiguration导入（Import）的条件。

NeedsWebSecurityCondition的```ConditionOutcome.inverse(super.getMatchOutcome(context, metadata));``` 这段代码刚好说明了取反了EnableOAuth2SsoCondition的条件。

所以这两个类不会被同时导入。

OAuth2SsoDefaultConfiguration 和 OAuth2SsoCustomConfiguration 最终都会用SsoSecurityConfigurer 这个类来配置HttpSecurit。区别是所使用的方法不同，并且OAuth2SsoDefaultConfiguration 默认会将所用的访问路径设置为必需经过认证。
OAuth2SsoDefaultConfiguration的代码片段
```java
@Override  
protected void configure(HttpSecurity http) throws Exception {  
	http.antMatcher("/**").authorizeRequests().anyRequest().authenticated();  
	new SsoSecurityConfigurer(this.applicationContext).configure(http);  
}
```

#### SsoSecurityConfigurer

SsoSecurityConfigurer完成了几件事

- 注册OAuth2ClientAuthenticationProcessingFilter过滤器
- 添加异常的defaultAuthenticationEntryPointFor

OAuth2ClientAuthenticationProcessingFilter加在AbstractPreAuthenticatedProcessingFilter之前

#### OAuth2ClientAuthenticationProcessingFilter

OAuth2ClientAuthenticationProcessingFilter继承自AbstractAuthenticationProcessingFilter，AbstractAuthenticationProcessingFilter的doFilter方法会调用attemptAuthentication来进行尝试认证，OAuth2ClientAuthenticationProcessingFilter改写了attemptAuthentication方法。

前面我们打了四个断点：
 - DefaultAccessTokenRequest
	 - getPreservedState
	 - setPreservedState 
 - DefaultOAuth2ClientContext
	 - setPreservedState
	 - removePreservedState

首先被触发的是DefaultAccessTokenRequest的setPreservedState。如果我们回溯调用栈的话，就会回到OAuth2ClientAuthenticationProcessingFilter的attemptAuthentication方法。

OAuth2ClientAuthenticationProcessingFilter的代码片段
```java
@Override  
public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)  
      throws AuthenticationException, IOException, ServletException {  
      
	OAuth2AccessToken accessToken;  
	try {  
	    accessToken = restTemplate.getAccessToken();  
	} catch (OAuth2Exception e) {  
		BadCredentialsException bad = new BadCredentialsException("Could not obtain access token", e);  
		publish(new OAuth2AuthenticationFailureEvent(bad));  
		throw bad;         
	}
}
```

```accessToken = restTemplate.getAccessToken(); ```会调用OAuth2RestTemplate的getAccessToken方法

OAuth2RestTemplate的代码片段
```java
public OAuth2AccessToken getAccessToken() throws UserRedirectRequiredException {  

	// 从Context中获取AccessToken
	OAuth2AccessToken accessToken = context.getAccessToken();  [1]

	// 如果没有AccessToken，或者AccessToken已经过期
	if (accessToken == null || accessToken.isExpired()) {  
		try {  
			accessToken = acquireAccessToken(context);  [2]
		}  
		catch (UserRedirectRequiredException e) {  
			context.setAccessToken(null); // No point hanging onto it now  
			accessToken = null;  
			String stateKey = e.getStateKey();  
			if (stateKey != null) {  
				Object stateToPreserve = e.getStateToPreserve();  
				if (stateToPreserve == null) {  
					stateToPreserve = "NONE";  
				}  
				context.setPreservedState(stateKey, stateToPreserve);  
			}  
			throw e;  
		}  
	}  
	return accessToken;  
}
```
[1]  这里首先会从context里获取AccessToken, 这里的Context是 DefaultOAuth2ClientContext， 它是由@EnableOAuth2Client注解导入的配置类OAuth2ClientConfiguration里面声明的一个Bean。这个Bean的Scope定义为session。所以它的生命周期与Http Session相关。
[2] 如果没有从Context取得AccessToken或者已经过期，那么调用acquireAccessToken方法继续获取

OAuth2RestTemplate的代码片段
```java
protected OAuth2AccessToken acquireAccessToken(OAuth2ClientContext oauth2Context)  
      throws UserRedirectRequiredException {  
  
	AccessTokenRequest accessTokenRequest = oauth2Context.getAccessTokenRequest();  
	if (accessTokenRequest == null) {  
		throw new AccessTokenRequiredException(  
		"No OAuth 2 security context has been established. Unable to access resource '"  
		+ this.resource.getId() + "'.", resource);  
	}  

	// Transfer the preserved state from the (longer lived) context to the current request.  
	String stateKey = accessTokenRequest.getStateKey();  
	if (stateKey != null) {  
		accessTokenRequest.setPreservedState(oauth2Context.removePreservedState(stateKey));  
	}  

	OAuth2AccessToken existingToken = oauth2Context.getAccessToken();  
	if (existingToken != null) {  
		accessTokenRequest.setExistingToken(existingToken);  
	}  

	OAuth2AccessToken accessToken = null;  
	accessToken = accessTokenProvider.obtainAccessToken(resource, accessTokenRequest);  
	if (accessToken == null || accessToken.getValue() == null) {  
		throw new IllegalStateException(  
		"Access token provider returned a null access token, which is illegal according to the contract.");  
	}  
	oauth2Context.setAccessToken(accessToken);  
	return accessToken;  
}
```
<!--stackedit_data:
eyJoaXN0b3J5IjpbLTE4OTAxNzA5OTZdfQ==
-->
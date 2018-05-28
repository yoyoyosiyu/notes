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
	accessToken = accessTokenProvider.obtainAccessToken(resource, accessTokenRequest); [1] 
	if (accessToken == null || accessToken.getValue() == null) {  
		throw new IllegalStateException(  
		"Access token provider returned a null access token, which is illegal according to the contract.");  
	}  
	oauth2Context.setAccessToken(accessToken);  
	return accessToken;  
}
```
一开始的时候还没有StateKey，这个SateKey是随机产生的一个字符串，如果稍微了解AuthorizationCode（授权码模式）的话，就知道当网站跳转到授权服务器网页的时候都会传过去一个state参数，当授权网站完成授权跳回请求授权的网站的时候，那么这个state参数的数值会原封不动的传回。我们知道HTTP是一个无状态的协议，当跳转到授权网站之后，然后再跳回来之后，请求授权的网站可以通过这个参数来判断是哪一次的请求，有点类似于会话标识符一样的意思，同时也可以判断这个会跳的授权是不是自己发出的。

[1] 通过AccessTokenProvider 调用obtainAccessToken来获取访问令牌(AccessToken)。这里的AccessTokenProvider 是
AuthorizationCodeAccessTokenProvider。（这里留下待解问题，为什么是AuthorizationCodeAccessTokenProvider？）

AuthorizationCodeAccessTokenProvider.java
```java
public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails details, AccessTokenRequest request)  
      throws UserRedirectRequiredException, UserApprovalRequiredException, AccessDeniedException,  
  OAuth2AccessDeniedException {  
  
	AuthorizationCodeResourceDetails resource = (AuthorizationCodeResourceDetails) details;  

	if (request.getAuthorizationCode() == null) {  
		if (request.getStateKey() == null) {  
			throw getRedirectForAuthorization(resource, request);  [1]
		}  
		obtainAuthorizationCode(resource, request); [2] 
	}  
	return retrieveToken(request, resource, getParametersForTokenRequest(resource, request),  
	getHeadersForTokenRequest(request)); [3]

}
```
这里会产生分支，如果没有授权码，也没有StateKey的话，那么将会通过抛出异常的方式去获取授权码[1]，如果没有授权码，但是有statekey的话，那么通过obtainAuthorizationCode获取授权码[2]，如果已经有授权码，那么通过retrieveToken来获取访问令牌[3]。

obtainAuthorizationCode是个非常有意思的方法，很值得研究。它是通过RestTemplate发送POST请求去获取授权码（AuthorizationCode），而不是通过网页跳转的方式，当然如果失败的话，它还是会回退到网页跳转的方式。由于代码太长，我们放到后面去研究。

一开始我们没有授权码，也没有StateKey，所以会执行[1]。接下来我们看看getRedirectForAuthorization会抛出什么的异常。

AuthorizationCodeAccessTokenProvider.java
```java
private UserRedirectRequiredException getRedirectForAuthorization(AuthorizationCodeResourceDetails resource,  
  AccessTokenRequest request) {  
  
	// we don't have an authorization code yet. So first get that.  
	TreeMap<String, String> requestParameters = new TreeMap<String, String>();  
	requestParameters.put("response_type", "code"); // oauth2 spec, section 3  
	requestParameters.put("client_id", resource.getClientId());  
	// Client secret is not required in the initial authorization request  

	String redirectUri = resource.getRedirectUri(request);  
	if (redirectUri != null) {  
		requestParameters.put("redirect_uri", redirectUri);  
	}  

	if (resource.isScoped()) {  

		StringBuilder builder = new StringBuilder();  
		List<String> scope = resource.getScope();  

		if (scope != null) {  
			Iterator<String> scopeIt = scope.iterator();  
			while (scopeIt.hasNext()) {  
				builder.append(scopeIt.next());  
				if (scopeIt.hasNext()) {  
					builder.append(' ');  
				}  
			}  
		}  

		requestParameters.put("scope", builder.toString());  
	}  

	UserRedirectRequiredException redirectException = new UserRedirectRequiredException(  
	resource.getUserAuthorizationUri(), requestParameters);  [1]

	String stateKey = stateKeyGenerator.generateKey(resource);  [2]
	redirectException.setStateKey(stateKey);  [3]
	request.setStateKey(stateKey);  
	redirectException.setStateToPreserve(redirectUri);  
	request.setPreservedState(redirectUri);  

	return redirectException;  
  
}
```

[1] 首先是构建了重定向所需要的请求参数：response_type、client_id、redirect_uri、state， 然后创建一个UserRedirectRequiredException 异常对象，并且把请求参数交给它。

[2] 这时候创建StateKey

[3] 同时将StateKey和PreservedState设置给AccessTokenRequest和UserRedirectRequiredException 异常。PreservedState的值就是redirectUri

异常被抛出后，我们再沿着调用栈往外追索，看看UserRedirectRequiredException 的异常将会再哪里被捕获并且被处理。

第一次捕获在OAuth2RestTemplate的getAccessToken方法
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
这里比较关键的就是它会将stateKey和statePreserve存入context（OAuth2ClientContext ），然后继续抛出。

我们再沿着调用栈往外走，看看在哪里会被捕获？

我一开始也没有找到，因为我的注意力只是集中在OAuth2ClientAuthenticationProcessingFilter这个过滤器上，我用F8键跟着代码的执行，最后终于发现了踪迹。它就在OAuth2ClientContextFilter的doFilter上。

OAuth2ClientContextFilter.java
```java
public void doFilter(ServletRequest servletRequest,  
  ServletResponse servletResponse, FilterChain chain)  
      throws IOException, ServletException {  
	HttpServletRequest request = (HttpServletRequest) servletRequest;  
	HttpServletResponse response = (HttpServletResponse) servletResponse;  
	request.setAttribute(CURRENT_URI, calculateCurrentUri(request));  

	try {  
		chain.doFilter(servletRequest, servletResponse);  
	} catch (IOException ex) {  
		throw ex;  
	} catch (Exception ex) {  
		// Try to extract a SpringSecurityException from the stacktrace  
		Throwable[] causeChain = throwableAnalyzer.determineCauseChain(ex);  
		UserRedirectRequiredException redirect = (UserRedirectRequiredException) throwableAnalyzer  
		.getFirstThrowableOfType(UserRedirectRequiredException.class, causeChain);  
		if (redirect != null) {  
			redirectUser(redirect, request, response);  
		} else {  
			if (ex instanceof ServletException) {  
				throw (ServletException) ex;  
			}  
			if (ex instanceof RuntimeException) {  
				throw (RuntimeException) ex;  
			}  
			throw new NestedServletException("Unhandled exception", ex);  
		}  
	}  
}
```
回到本篇文章的最开始，我们已经知道OAuth2ClientContextFilter是OAuth2ClientConfiguration配置类声明的Bean。


#### OAuth2ClientContextFilter
它的主要作用就是处理UserRedirectRequiredException，重定向到授权网站。

如果不使用Spring Boot的话，那么只能使用EnableOAuth2Client，而不能使用EnableOAuth2Ssso，因为EnableOAuth2Sso是spring-security-oauth2-autoconfigure中定义的，spring-security-oauth2-autoconfigure的自动配置必须要使用到Spring Boot的自动配置机制。

如果不使用spring-security-oauth2-autoconfigure，那么我们应该要定义一个DelegatingFilterProxy。如果用spring-security-oauth2-autoconfigure的话，那么自动化配置会配置好这个过滤器。

根据Spring Boot 对Jar包的自动化配置机制，那么在Jar包中的META-INF文件夹中要有spring.factories文件，文件中的org.springframework.boot.autoconfigure.EnableAutoConfiguration键指定了全域名限定的类名作为自动话配置的配置类，spring-security-oauth2-autoconfigure的JAR包中的spring.factories文件内容如下
```
# Auto Configure  
org.springframework.boot.autoconfigure.EnableAutoConfiguration=\  
org.springframework.boot.autoconfigure.security.oauth2.OAuth2AutoConfiguration
```

OAuth2AutoConfiguration.java

```java
@Configuration  
@ConditionalOnClass({ OAuth2AccessToken.class, WebMvcConfigurer.class })  
@Import({ OAuth2AuthorizationServerConfiguration.class,  
  OAuth2MethodSecurityConfiguration.class, OAuth2ResourceServerConfiguration.class,  
  OAuth2RestOperationsConfiguration.class })  
@AutoConfigureBefore(WebMvcAutoConfiguration.class)  
@EnableConfigurationProperties(OAuth2ClientProperties.class)  
public class OAuth2AutoConfiguration {  
  
	private final OAuth2ClientProperties credentials;  

	public OAuth2AutoConfiguration(OAuth2ClientProperties credentials) {  
		this.credentials = credentials;  
	}  

	@Bean  
	public ResourceServerProperties resourceServerProperties() {  
		return new ResourceServerProperties(this.credentials.getClientId(),  
		this.credentials.getClientSecret());  
	}  
}
```
OAuth2ClientContextFilter是通过OAuth2RestOperationsConfiguration加入过滤器链的。

OAuth2RestOperationsConfiguration.java
```java
@Configuration  
@ConditionalOnBean(OAuth2ClientConfiguration.class)  
@Conditional({ OAuth2ClientIdCondition.class, NoClientCredentialsCondition.class })  
@Import(OAuth2ProtectedResourceDetailsConfiguration.class)  
protected static class SessionScopedConfiguration {  
  
	@Bean  
	public FilterRegistrationBean<OAuth2ClientContextFilter> oauth2ClientFilterRegistration(  
	OAuth2ClientContextFilter filter, SecurityProperties security) {  
		FilterRegistrationBean<OAuth2ClientContextFilter> registration = new FilterRegistrationBean<>();  
		registration.setFilter(filter);  
		registration.setOrder(security.getFilter().getOrder() - 10);  
		return registration;  
	}  

	@Configuration  
	protected static class ClientContextConfiguration {  

		private final AccessTokenRequest accessTokenRequest;  

		public ClientContextConfiguration(  
		@Qualifier("accessTokenRequest") ObjectProvider<AccessTokenRequest> accessTokenRequest) {  
			this.accessTokenRequest = accessTokenRequest.getIfAvailable();  
		}  

		@Bean  
		@Scope(value = "session", proxyMode = ScopedProxyMode.INTERFACES)  
		public DefaultOAuth2ClientContext oauth2ClientContext() {  
			return new DefaultOAuth2ClientContext(this.accessTokenRequest);  
		}  
	}  
}
```
这里需要注意两个地方：
	- @ConditionalOnBean(OAuth2ClientConfiguration.class)  
	- oauth2ClientFilterRegistration

回忆一下，OAuth2ClientConfiguration正是EnableOAuth2Client导入的配置类。而OAuth2ClientContextFilter是OAuth2ClientConfiguration声明的一个Bean。oauth2ClientFilterRegistration声明的Bean所需要的其中一个参数的类型正是OAuth2ClientContextFilter，所以OAuth2ClientConfiguration声明的那个OAuth2ClientContextFilter的Bean将会注入到这个参数值当中，然后通过FilterRegistrationBean来添加到过滤器链中。

> Spring 提供了FilterRegistrationBean类，此类提供setOrder方法，可以为filter设置排序值，让spring在注册web filter之前排序后再依次注册。

除此之外我们还要注意一个单例的Bean：oauth2RemoteResource，它的类型是ClientCredentialsResourceDetails
```java
@Bean  
@ConfigurationProperties(prefix = "security.oauth2.client")  
@Primary  
public ClientCredentialsResourceDetails oauth2RemoteResource() {  
	ClientCredentialsResourceDetails details = new ClientCredentialsResourceDetails();  
	return details;  
}
```
要注意的是@ConfigurationProperties，它会将application.properties或者application.yml配置文件中security.oauth2.client下的配置信息设置到ClientCredentialsResourceDetails对应的属性中。
<!--stackedit_data:
eyJoaXN0b3J5IjpbMjExMTAwNjI4NywxNjQwMjkwNDM0XX0=
-->
### Spring Boot Security OAuth2 的源码研究

#### 入口 @EnableOAuth2Client

最好的JAVA开发工具还是Intellij Idea。按住ALT键，然后将鼠标移至你想查看的类型上面，会高亮显示带下划线。然后点击即可打开这个类型的类定义文件。没有源码也可以，Intellij 会帮你反编译，如果有源码，那么就会打开源码。你可以打断点调试，非常的厉害。

@EnableOAuth2Client Import了OAuth2ClientConfiguration， OAuth2ClientConfiguration是个配置类

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

<!--stackedit_data:
eyJoaXN0b3J5IjpbMTQ5NDk5NjMwN119
-->
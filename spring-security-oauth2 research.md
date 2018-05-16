# Spring Security OAuth 

[![N|Solid](https://cldup.com/dTxpPi9lDf.thumb.png)](https://nodesource.com/products/nsolid)

这篇文章是研究Spring Security OAuth 源代码的手稿

源码的地址

  - spring security: [https://github.com/spring-projects/spring-security](https://github.com/spring-projects/spring-security)
  - spring security oauth: [https://github.com/spring-projects/spring-security-oauth](https://github.com/spring-projects/spring-security-oauth)

本文的Github地址
[https://github.com/yoyoyosiyu/notes/blob/master/spring-security-oauth2 research.md](https://github.com/yoyoyosiyu/notes/blob/master/spring-security-oauth2%20research.md "github 地址")

# 代码入口

- @EnableAuthorizationServer
- @EnableOAuth2Client
- @EnableResourceServer

### @EnableAuthorizationServer

代码的定义在：org/springframework/security/oauth2/config/annotation/web/configuration/EnableAuthorizationServer.java

```java
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import({AuthorizationServerEndpointsConfiguration.class, AuthorizationServerSecurityConfiguration.class})
public @interface EnableAuthorizationServer {

}
```
**@EnableAuthorizationServer**注解的定义通过@Import导入了两个重要的类：`AuthorizationServerSecurityConfiguration`和 `AuthorizationServerEndpointsConfiguration`

> @Import在Spring 4.2之前只能作用在接口类上，4.2之后可以作用在普通的类。通过@Import的普通类会自动注册为一个Bean

### AuthorizationServerSecurityConfiguration类
代码片段
```java
@Configuration
@Order(0)
@Import({ ClientDetailsServiceConfiguration.class, AuthorizationServerEndpointsConfiguration.class })
public class AuthorizationServerSecurityConfiguration extends WebSecurityConfigurerAdapter {
```
这里要注意两个地方：
  - @Order注解
  - 继承自**WebSecurityConfigurerAdapter**

如果了解Spring Security的话，我们知道Spring Security通过WebSecurityConfigurerAdapter来进行配置。允许多个WebSecurityConfigurerAdapter以及其衍生类的实例存在
多个实例是通过@Order注解来控制器其优先级的。Oder的值越小，其优先级越高。Sping Security OAuth的优先级别设为0，如果我们的项目要定义自己的WebSecurityConfigurerAdapter
那么order值就要设置小于0，否则优先级别会低于AuthorizationServerSecurityConfiguration的实例。

对于派生自**WebSecurityConfigurerAdapter**的类型，最主要是要重载3个方法：
  - configure(HttpSecurity http)
  - configure(AuthenticationManagerBuilder auth)
  - configure(WebSecurity web)

AuthorizationServerSecurityConfiguration主要重载 configure(HttpSecurity http)这个方法
```java
@Override
	protected void configure(HttpSecurity http) throws Exception {
		AuthorizationServerSecurityConfigurer configurer = new AuthorizationServerSecurityConfigurer();
		FrameworkEndpointHandlerMapping handlerMapping = endpoints.oauth2EndpointHandlerMapping();
		http.setSharedObject(FrameworkEndpointHandlerMapping.class, handlerMapping);
		configure(configurer);
		http.apply(configurer);
		String tokenEndpointPath = handlerMapping.getServletPath("/oauth/token");
		String tokenKeyPath = handlerMapping.getServletPath("/oauth/token_key");
		String checkTokenPath = handlerMapping.getServletPath("/oauth/check_token");
		if (!endpoints.getEndpointsConfigurer().isUserDetailsServiceOverride()) {
			UserDetailsService userDetailsService = http.getSharedObject(UserDetailsService.class);
			endpoints.getEndpointsConfigurer().userDetailsService(userDetailsService);
		}
		// @formatter:off
		http
        	.authorizeRequests()
            	.antMatchers(tokenEndpointPath).fullyAuthenticated()
            	.antMatchers(tokenKeyPath).access(configurer.getTokenKeyAccess())
            	.antMatchers(checkTokenPath).access(configurer.getCheckTokenAccess())
        .and()
        	.requestMatchers()
            	.antMatchers(tokenEndpointPath, tokenKeyPath, checkTokenPath)
        .and()
        	.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER);
		// @formatter:on
		http.setSharedObject(ClientDetailsService.class, clientDetailsService);
	}
```
从这段代码可以看到了Spring Security OAuth的默认安全设置
  - /oauth/token 必须fullyAuthenticated
  - /oauth/token_key 可以通过AuthorizationServerSecurityConfigurer来设置
  - /oauth/check_token 可以通过AuthorizationServerSecurityConfigurer来设置

这里要理清几个类的关系
 **AuthorizationServerSecurityConfiguration** 
  -> **AuthorizationServerSecurityConfigurer** 
    -> **AuthorizationServerConfigurer**

类的名字看上去都非常的相似，要仔细辨认才能看出其中的不同。这里梳理一下他们的关系，对我们理解代码有很大的帮助。
**AuthorizationServerSecurityConfigurer**在**AuthorizationServerSecurityConfiguration**类的configure(HttpSecurity http)方法中创建，而**AuthorizationServerConfigurer**可以由我们的自己的项目定义，然后声明为Bean。**AuthorizationServerSecurityConfiguration** 会收集所有
类型为**AuthorizationServerConfigurer**的Bean,下面的代码摘自**AuthorizationServerSecurityConfiguration**的定义
```java
    @Autowired
	private List<AuthorizationServerConfigurer> configurers = Collections.emptyList();
```
**AuthorizationServerSecurityConfiguration**创建了**AuthorizationServerSecurityConfigurer**类之后，会调用configure(AuthorizationServerSecurityConfigurer oauthServer)
方法，这个方法是**AuthorizationServerSecurityConfiguration**自己定义的方法，并不是**WebSecurityConfigurerAdapter**重载的方法，虽然看上去和其他的configure有点像。
这个方法的作用很简单，就是逐个调用**AuthorizationServerConfigurer**（少Security单词，区分与**AuthorizationServerSecurityConfigurer**）的configure方法，并且将**AuthorizationServerSecurityConfigurer**实例通过参数传递给**AuthorizationServerConfigurer**处理。
```java
    protected void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
		for (AuthorizationServerConfigurer configurer : configurers) {
			configurer.configure(oauthServer);
		}
	}
```

这样我们就大致理清了这三者的关系
**AuthorizationServerSecurityConfiguration** 通过自动连线的方式获得了所有已经注册了的**AuthorizationServerConfigurer**的Bean的列表，然后创建一个**AuthorizationServerSecurityConfigurer**
然后将其交给每一个**AuthorizationServerConfigurer**处理，然后**AuthorizationServerConfigurer**会配置这个**AuthorizationServerSecurityConfigurer**对象，
最后**AuthorizationServerSecurityConfiguration**会将**AuthorizationServerSecurityConfigurer**这个经过配置的对象交给HttpSecurity对象去处理,因为**AuthorizationServerSecurityConfigurer**派生自Spring Security的**SecurityConfigurerAdapter**类。
```java
    http.apply(configurer);
```


### AuthorizationServerSecurityConfigurer类

从这里可以看出AuthorizationServerSecurityConfigurer这个对象的重要性，这个对象的定义在：
```
org/springframework/security/oauth2/config/annotation/web/configurers/AuthorizationServerSecurityConfigurer.java
```

根据我们的经验，对于这中种类型的配置类，我们应该要关注那些那些重载的函数方法，道理很简单，因为重载的方法才是“与众不同”的地方。

**AuthorizationServerSecurityConfigurer**重载了两个方法：
  - init(HttpSecurity http)
  - configure(HttpSecurity http)

#### init
先看看init都做了什么
```java
    @Override
	public void init(HttpSecurity http) throws Exception {

		registerDefaultAuthenticationEntryPoint(http);
		if (passwordEncoder != null) {
			ClientDetailsUserDetailsService clientDetailsUserDetailsService = new ClientDetailsUserDetailsService(clientDetailsService());
			clientDetailsUserDetailsService.setPasswordEncoder(passwordEncoder());
			http.getSharedObject(AuthenticationManagerBuilder.class)
					.userDetailsService(clientDetailsUserDetailsService)
					.passwordEncoder(passwordEncoder());
		}
		else {
			http.userDetailsService(new ClientDetailsUserDetailsService(clientDetailsService()));
		}
		http.securityContext().securityContextRepository(new NullSecurityContextRepository()).and().csrf().disable()
				.httpBasic().realmName(realm);
		if (sslOnly) {
			http.requiresChannel().anyRequest().requiresSecure();
		}
	}
```

 - 注册默认的认证入口(这里不深入研究代码，放到configure之后才深挖代码)
 - 如果passwordEncoder存在的话，那么设置UserDetailsService和 PasswordEncoder，否则只是设置UserDetailsService。（这里引入了ClientDetailsUserDetailsService）
 - 设置securityContextRepository
 - 关闭 csrf
 - 打开 HttpBasic 认证方式
 - 设置 realm
 - 如果设置了只允许SSL的话，那么设置所有请求都需要Secure

#### configure
接下来我们看看configure重载方法做了些什么
```java
    @Override
	public void configure(HttpSecurity http) throws Exception {
		
		// ensure this is initialized
		frameworkEndpointHandlerMapping();
		if (allowFormAuthenticationForClients) {
			clientCredentialsTokenEndpointFilter(http);
		}

		for (Filter filter : tokenEndpointAuthenticationFilters) {
			http.addFilterBefore(filter, BasicAuthenticationFilter.class);
		}

		http.exceptionHandling().accessDeniedHandler(accessDeniedHandler);
	}
```
  - 确保FrameworkEndpoint已经被初始化
  - 如果allowFormAuthenticationForClients被设置为允许的话，那么允许... **（这里忘了怎么描述）**
  - 如果有TokenEndpointAuthenticationFilter过滤器的话，添加到 BasicAuthenticationFilter之前
  - 设置Access Denied 处理器
  - 
  
SpringMVC源码总结（一）HandlerMapping和HandlerAdapter入门
https://blog.csdn.net/zljjava/article/details/50414585

HandlerMapping 详解
https://www.cnblogs.com/dragonfei/p/6148625.html

Spring自定义RequestMappingHandlerMapping避免PathVariable的性能低下
https://www.jianshu.com/p/5574cb427140

springmvc RequestMappingHandlerMapping初始化详解
https://www.cnblogs.com/BINGJJFLY/p/7452717.html

如何实例化requestmappinghandlermapping类
https://zhidao.baidu.com/question/372438141876783604.html

Dillinger is a cloud-enabled, mobile-ready, offline-storage, AngularJS powered HTML5 Markdown editor.

  - Type some Markdown on the left
  - See HTML in the right
  - Magic

# New Features!

  - Import a HTML file and watch it magically convert to Markdown
  - Drag and drop images (requires your Dropbox account be linked)


You can also:
  - Import and save files from GitHub, Dropbox, Google Drive and One Drive
  - Drag and drop markdown and HTML files into Dillinger
  - Export documents as Markdown, HTML and PDF

Markdown is a lightweight markup language based on the formatting conventions that people naturally use in email.  As [John Gruber] writes on the [Markdown site][df1]

> The overriding design goal for Markdown's
> formatting syntax is to make it as readable
> as possible. The idea is that a
> Markdown-formatted document should be
> publishable as-is, as plain text, without
> looking like it's been marked up with tags
> or formatting instructions.

This text you see here is *actually* written in Markdown! To get a feel for Markdown's syntax, type some text into the left window and watch the results in the right.

### Tech

Dillinger uses a number of open source projects to work properly:

* [AngularJS] - HTML enhanced for web apps!
* [Ace Editor] - awesome web-based text editor
* [markdown-it] - Markdown parser done right. Fast and easy to extend.
* [Twitter Bootstrap] - great UI boilerplate for modern web apps
* [node.js] - evented I/O for the backend
* [Express] - fast node.js network app framework [@tjholowaychuk]
* [Gulp] - the streaming build system
* [Breakdance](http://breakdance.io) - HTML to Markdown converter
* [jQuery] - duh

And of course Dillinger itself is open source with a [public repository][dill]
 on GitHub.

### Installation

Dillinger requires [Node.js](https://nodejs.org/) v4+ to run.

Install the dependencies and devDependencies and start the server.

```sh
$ cd dillinger
$ npm install -d
$ node app
```

For production environments...

```sh
$ npm install --production
$ NODE_ENV=production node app
```

### Plugins

Dillinger is currently extended with the following plugins. Instructions on how to use them in your own application are linked below.

| Plugin | README |
| ------ | ------ |
| Dropbox | [plugins/dropbox/README.md][PlDb] |
| Github | [plugins/github/README.md][PlGh] |
| Google Drive | [plugins/googledrive/README.md][PlGd] |
| OneDrive | [plugins/onedrive/README.md][PlOd] |
| Medium | [plugins/medium/README.md][PlMe] |
| Google Analytics | [plugins/googleanalytics/README.md][PlGa] |


### Development

Want to contribute? Great!

Dillinger uses Gulp + Webpack for fast developing.
Make a change in your file and instantanously see your updates!

Open your favorite Terminal and run these commands.

First Tab:
```sh
$ node app
```

Second Tab:
```sh
$ gulp watch
```

(optional) Third:
```sh
$ karma test
```
#### Building for source
For production release:
```sh
$ gulp build --prod
```
Generating pre-built zip archives for distribution:
```sh
$ gulp build dist --prod
```
### Docker
Dillinger is very easy to install and deploy in a Docker container.

By default, the Docker will expose port 8080, so change this within the Dockerfile if necessary. When ready, simply use the Dockerfile to build the image.

```sh
cd dillinger
docker build -t joemccann/dillinger:${package.json.version}
```
This will create the dillinger image and pull in the necessary dependencies. Be sure to swap out `${package.json.version}` with the actual version of Dillinger.

Once done, run the Docker image and map the port to whatever you wish on your host. In this example, we simply map port 8000 of the host to port 8080 of the Docker (or whatever port was exposed in the Dockerfile):

```sh
docker run -d -p 8000:8080 --restart="always" <youruser>/dillinger:${package.json.version}
```

Verify the deployment by navigating to your server address in your preferred browser.

```sh
127.0.0.1:8000
```

#### Kubernetes + Google Cloud

See [KUBERNETES.md](https://github.com/joemccann/dillinger/blob/master/KUBERNETES.md)


### Todos

 - Write MORE Tests
 - Add Night Mode

License
----

MIT


**Free Software, Hell Yeah!**

<span id="AuthorizationServerEndpointsConfiguration"></span>

[//]: # (These are reference links used in the body of this note and get stripped out when the markdown processor does its job. There is no need to format nicely because it shouldn't be seen. Thanks SO - http://stackoverflow.com/questions/4823468/store-comments-in-markdown-syntax)


   [dill]: <https://github.com/joemccann/dillinger>
   [git-repo-url]: <https://github.com/joemccann/dillinger.git>
   [john gruber]: <http://daringfireball.net>
   [df1]: <http://daringfireball.net/projects/markdown/>
   [markdown-it]: <https://github.com/markdown-it/markdown-it>
   [Ace Editor]: <http://ace.ajax.org>
   [node.js]: <http://nodejs.org>
   [Twitter Bootstrap]: <http://twitter.github.com/bootstrap/>
   [jQuery]: <http://jquery.com>
   [@tjholowaychuk]: <http://twitter.com/tjholowaychuk>
   [express]: <http://expressjs.com>
   [AngularJS]: <http://angularjs.org>
   [Gulp]: <http://gulpjs.com>

   [PlDb]: <https://github.com/joemccann/dillinger/tree/master/plugins/dropbox/README.md>
   [PlGh]: <https://github.com/joemccann/dillinger/tree/master/plugins/github/README.md>
   [PlGd]: <https://github.com/joemccann/dillinger/tree/master/plugins/googledrive/README.md>
   [PlOd]: <https://github.com/joemccann/dillinger/tree/master/plugins/onedrive/README.md>
   [PlMe]: <https://github.com/joemccann/dillinger/tree/master/plugins/medium/README.md>
   [PlGa]: <https://github.com/RahulHP/dillinger/blob/master/plugins/googleanalytics/README.md>

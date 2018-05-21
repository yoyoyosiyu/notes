# Spring Web & MVC 研究

源码：
[https://github.com/spring-projects/spring-framework](https://github.com/spring-projects/spring-framework)

我们的研究以Spring Web 作为研究的起点，Spring MVC是建立在Spring Web的基础上的。这两个都是Spring Framework 的两个自子项目。

## 入口
spring-web项目的 org/springframework/web/SpringServletContainerInitializer.java
```java
@HandlesTypes(WebApplicationInitializer.class)
public class SpringServletContainerInitializer implements ServletContainerInitializer {

	/**
	 * 省略一大段英文注释
	 */
	@Override
	public void onStartup(@Nullable Set<Class<?>> webAppInitializerClasses, ServletContext servletContext)
			throws ServletException {

		List<WebApplicationInitializer> initializers = new LinkedList<>();

		if (webAppInitializerClasses != null) {
			for (Class<?> waiClass : webAppInitializerClasses) {
				// Be defensive: Some servlet containers provide us with invalid classes,
				// no matter what @HandlesTypes says...
				if (!waiClass.isInterface() && !Modifier.isAbstract(waiClass.getModifiers()) &&
						WebApplicationInitializer.class.isAssignableFrom(waiClass)) {
					try {
						initializers.add((WebApplicationInitializer)
								ReflectionUtils.accessibleConstructor(waiClass).newInstance());
					}
					catch (Throwable ex) {
						throw new ServletException("Failed to instantiate WebApplicationInitializer class", ex);
					}
				}
			}
		}

		if (initializers.isEmpty()) {
			servletContext.log("No Spring WebApplicationInitializer types detected on classpath");
			return;
		}

		servletContext.log(initializers.size() + " Spring WebApplicationInitializers detected on classpath");
		AnnotationAwareOrderComparator.sort(initializers);
		for (WebApplicationInitializer initializer : initializers) {
			initializer.onStartup(servletContext);
		}
	}

}
```

ServletContainerInitializer之所以能成为Spring-Web的入口文件，这里涉及到Servlet 3.0 的一个新的特性：共享库 / 运行时可插拔性(8.2.4章节)
servlet 3.1 规范的原文和译文地址如下：
原文：[http://download.oracle.com/otndocs/jcp/servlet-3_1-fr-eval-spec/index.html](http://download.oracle.com/otndocs/jcp/servlet-3_1-fr-eval-spec/index.html)
译文：[https://blog.csdn.net/mhmyqn/article/details/8551797](https://blog.csdn.net/mhmyqn/article/details/8551797)

> 从Servlet 3.1 开始，容器引入了共享库/运行时可插拔性。原理是当容器启动的时候，容器会通过jar services API查找一个ServletContainerInitializer实例。而查找的位置是
> 应用所使用的jar包（WEB-INF/lib下的jar文件),这里一定要注意不是打包WEB应用的JAR包。jar services API会看看
> JAR包有没有META-INF/services/javax.servlet.ServletContainerInitializer文件，如果有的话，那么文件的内容应该是ServletContainerInitializer的实际实现类名称
> 例如：Spring-Web的META-INF/services/javax.servlet.ServletContainerInitializer文件内容为：
> org.springframework.web.SpringServletContainerInitializer

下面是一个比较完整的例子
```
MyWebApp.war!
   WEB-INF
       lib
           MyWebFrameworkLib.jar!
               WEB-INF
                   classes
                       com
                           huayutech
                               MyServletContainerInitializer.class
               META-INF
                   services
                       javax.servlet.ServletContainerInitializer
                           (com.huayutech.MyServletContainerInitializer)
       classes
```

在任何Listener的事件被触发之前，当应用正在启动时，ServletContainerInitializer的onStartup方法将被调用。

除此之外容器还会将所有实现了@HandlesTypes注解所指定的接口类的实现类或者衍生类的实例通过onStartup方法的第一个参数传递给onStartup方式处理。Spring-Web所指定的接口类
是WebApplicationInitializer(org/springframework/web/WebApplicationInitializer.java)

Spring-Web 提供了一个抽象类
org/springframework/web/context/AbstractContextLoaderInitializer.java
```java
public abstract class AbstractContextLoaderInitializer implements WebApplicationInitializer {

	/** Logger available to subclasses */
	protected final Log logger = LogFactory.getLog(getClass());


	@Override
	public void onStartup(ServletContext servletContext) throws ServletException {
		registerContextLoaderListener(servletContext);
	}

	/**
	 * Register a {@link ContextLoaderListener} against the given servlet context. The
	 * {@code ContextLoaderListener} is initialized with the application context returned
	 * from the {@link #createRootApplicationContext()} template method.
	 * @param servletContext the servlet context to register the listener against
	 */
	protected void registerContextLoaderListener(ServletContext servletContext) {
		WebApplicationContext rootAppContext = createRootApplicationContext();
		if (rootAppContext != null) {
			ContextLoaderListener listener = new ContextLoaderListener(rootAppContext);
			listener.setContextInitializers(getRootApplicationContextInitializers());
			servletContext.addListener(listener);
		}
		else {
			logger.debug("No ContextLoaderListener registered, as " +
					"createRootApplicationContext() did not return an application context");
		}
	}

	/**
	 * Create the "<strong>root</strong>" application context to be provided to the
	 * {@code ContextLoaderListener}.
	 * <p>The returned context is delegated to
	 * {@link ContextLoaderListener#ContextLoaderListener(WebApplicationContext)} and will
	 * be established as the parent context for any {@code DispatcherServlet} application
	 * contexts. As such, it typically contains middle-tier services, data sources, etc.
	 * @return the root application context, or {@code null} if a root context is not
	 * desired
	 * @see org.springframework.web.servlet.support.AbstractDispatcherServletInitializer
	 */
	@Nullable
	protected abstract WebApplicationContext createRootApplicationContext();

	/**
	 * Specify application context initializers to be applied to the root application
	 * context that the {@code ContextLoaderListener} is being created with.
	 * @since 4.2
	 * @see #createRootApplicationContext()
	 * @see ContextLoaderListener#setContextInitializers
	 */
	@Nullable
	protected ApplicationContextInitializer<?>[] getRootApplicationContextInitializers() {
		return null;
	}

}
```

而 Spring-MVC 实现了另外两个
Spring-MVC: org/springframework/web/servlet/support/AbstractDispatcherServletInitializer.java
Spring-MVC: org/springframework/web/servlet/support/AbstractAnnotationConfigDispatcherServletInitializer.java

AbstractDispatcherServletInitializer继承自AbstractContextLoaderInitializer，而AbstractAnnotationConfigDispatcherServletInitializer继承自AbstractDispatcherServletInitializer，那么整个关系如下：
```
    WebApplicationInitializer
        AbstractContextLoaderInitializer
            AbstractDispatcherServletInitializer
                AbstractAnnotationConfigDispatcherServletInitializer
```

AbstractDispatcherServletInitializer和AbstractAnnotationConfigDispatcherServletInitializer我们留待解析Spring-MVC的时候研究。这里我们要看看AbstractContextLoaderInitializer做了什么？

AbstractContextLoaderInitializer做的工作很简单，注册一个监听器ContextLoaderListener。
ContextLoaderListener实现了标准的监听器接口ServletContextListener，并且扩展自ContextLoader。大部分的工作有ContextLoader来由实现，ContextLoaderListener像一个粘合剂，将ContextLoader和ServletContextListenern粘合在一起：
```java
org/springframework/web/context/ContextLoaderListener.java
public class ContextLoaderListener extends ContextLoader implements ServletContextListener {

	
	public ContextLoaderListener() {
	}

	public ContextLoaderListener(WebApplicationContext context) {
		super(context);
	}

	@Override
	public void contextInitialized(ServletContextEvent event) {
		initWebApplicationContext(event.getServletContext());
	}

	@Override
	public void contextDestroyed(ServletContextEvent event) {
		closeWebApplicationContext(event.getServletContext());
		ContextCleanupListener.cleanupAttributes(event.getServletContext());
	}
}
```
其中initWebApplicationContext和closeWebApplicationContext都在ContextLoader中实现
```java
org/springframework/web/context/ContextLoader.java
public class ContextLoader {

    public WebApplicationContext initWebApplicationContext(ServletContext servletContext) {
    
        // 只列了两行关键的代码
        this.context = createWebApplicationContext(servletContext);
        configureAndRefreshWebApplicationContext(cwac, servletContext);
    
    }

}
```






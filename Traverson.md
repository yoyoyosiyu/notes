
# 使用Traverson来访问HATEOAS

我们可以使用Traverson来非常方便的在Spring应用中访问那些符合HATEOAS规范的Rest API接口。

Traverson 包含在Spring-HATEOAS中，在官方的网站有简单的说明文档：

https://docs.spring.io/spring-hateoas/docs/0.24.0.RELEASE/reference/html/

但如果只是按照官方的文档来做的话，其实在运行当中会出现很多错误。首先是依赖

```pom
<dependency>  
	<groupId>org.springframework.hateoas</groupId>  
	<artifactId>spring-hateoas</artifactId>  
</dependency>

<!-- 这两个依赖不能少 -->
<dependency>  
	<groupId>org.springframework.plugin</groupId>  
	<artifactId>spring-plugin-core</artifactId>  
	<version>1.2.0.RELEASE</version>  
</dependency>  
<dependency>  
	<groupId>com.jayway.jsonpath</groupId>  
	<artifactId>json-path</artifactId>  
	<version>2.4.0</version> 
</dependency>
``` 

其次在官方的文档中withParameter方法已经不存在，改为withTemplateParameters。

现在我们看看如何使用Traverson来访问我们的资源。

假设我们要访问的资源地址为：http://localhost:9091/users/search/account?account=hkcl&password=e10adc3949ba59abbe56e057f20f883e

那么我们可以：
```java
	Resources<MyObject> myObjects; 
	try {  
		Traverson traverson = new Traverson(new URI("http://localhost:9091/"), MediaTypes.HAL_JSON);  
		Map<String, Object> parameters = new HashMap<String, Object>();  
		parameters.put("account", "hkcl");  
		parameters.put("password", "e10adc3949ba59abbe56e057f20f883e");  

		ParameterizedTypeReference<Resources<MyObject>> resourceParameterizedTypeReference =  
		        new ParameterizedTypeReference<Resources<MyObject>>() {};  

		myObjects = traverson.follow("users", "search","account").withTemplateParameters(parameters).toObject(resourceParameterizedTypeReference);  
	  
	  
	} catch (URISyntaxException e) {  
	    e.printStackTrace();  
	}  
	catch (Exception e) {  
	    e.printStackTrace();  
	}
```
MyObject.java
```java
import lombok.Data;  
  
@Data  
public class MyObject {  
  
    public MyObject() {  
    }  
  
    private String account;  
  
}
```

> Written with [StackEdit](https://stackedit.io/).
<!--stackedit_data:
eyJoaXN0b3J5IjpbMjA2MjE2MzQ5OF19
-->
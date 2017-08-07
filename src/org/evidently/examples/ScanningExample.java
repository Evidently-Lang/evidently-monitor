package org.evidently.examples;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.URLConnection;

import org.evidently.annotations.ReleasePolicyFor;

public class ScanningExample extends URLClassLoader{

	public ScanningExample(URL[] urls) {
		super(urls);
		// TODO Auto-generated constructor stub
	}
	
	public void doIt(){
		try {
            String url = "file:bin/org/evidently/policy/numberguesser/PolicyReleaseGuessesToAdmin.class";
            URL myUrl = new URL(url);
            URLConnection connection = myUrl.openConnection();
            InputStream input = connection.getInputStream();
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            int data = input.read();

            while(data != -1){
                buffer.write(data);
                data = input.read();
            }

            input.close();

            byte[] classData = buffer.toByteArray();

            Class c =  defineClass("org.evidently.policy.numberguesser.PolicyReleaseGuessesToAdmin",
                    classData, 0, classData.length);
            
            Method[] mz = c.getMethods();
            
    		for(Method m : mz){
    			if(m.isAnnotationPresent(ReleasePolicyFor.class)){
    				System.out.println("OK!");
    			}
    		}

        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

		
		
	}



	public static void main(String[] args) throws MalformedURLException, ClassNotFoundException {

		
//		Reflections reflections = new Reflections(new ConfigurationBuilder()
//			     .setUrls(ClasspathHelper.forPackage("org.evidently.policy"))
//			     .setScanners(new SubTypesScanner(), 
//			                  new TypeAnnotationsScanner(),
//			                  new MethodAnnotationsScanner()
//			    		 ));
//		
//		Set<Method> methods = reflections.getMethodsAnnotatedWith(ReleasePolicyFor.class);
//
//		for(Method m : methods){
//			
//			ReleasePolicyFor rpFor = (ReleasePolicyFor) m.getAnnotation(ReleasePolicyFor.class);
//
//			System.out.println(rpFor.value());
//			if(1==1){
//				continue;
//			}			
//		}
		String url = "file:bin/org/evidently/policy/numberguesser/PolicyReleaseGuessesToAdmin.class";
        URL myUrl = new URL(url);
        URL [] urls = new URL[]{myUrl};
        
		@SuppressWarnings("resource")
		ScanningExample e = new ScanningExample(urls);
		e.doIt();
		
		
		
		if(1==1)
		{
			return;
		}
		
	}
	
	
	
//	public static class ByteClassLoader extends URLClassLoader {
//	    //private final Map<String, byte[]> extraClassDefs;
//
//	    public ByteClassLoader(URL[] urls, ClassLoader parent, Map<String, byte[]> extraClassDefs) {
//	      super(urls);
//	      //this.extraClassDefs = new HashMap<String, byte[]>(extraClassDefs);
//	    }
//
//	    @Override
//	    protected Class<?> findClass(final String name) throws ClassNotFoundException {
//	      byte[] classBytes = this.extraClassDefs.remove(name);
//	      if (classBytes != null) {
//	        return defineClass(name, classBytes, 0, classBytes.length); 
//	      }
//	      return super.findClass(name);
//	    }
//
//	  }

}

package org.slf4j;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.amazon.device.ads.DtbConstants;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.net.URL;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;
import java.util.concurrent.LinkedBlockingQueue;
import org.slf4j.helpers.e;
import org.slf4j.helpers.g;
import org.slf4j.helpers.h;
import org.slf4j.helpers.i;
import org.slf4j.helpers.j;
import org.slf4j.helpers.k;

/* loaded from: classes3.dex */
public abstract class d {
    public static volatile int a;
    public static final e b = new e(1);
    public static final e c = new e(0);
    public static final boolean d;
    public static volatile org.slf4j.spi.a e;
    public static final String[] f;

    static {
        String property;
        try {
            property = System.getProperty("slf4j.detectLoggerNameMismatch");
        } catch (SecurityException unused) {
            property = null;
        }
        d = property == null ? false : property.equalsIgnoreCase("true");
        f = new String[]{DtbConstants.APS_ADAPTER_VERSION_2};
    }

    public static ArrayList a() {
        ArrayList arrayList = new ArrayList();
        final ClassLoader classLoader = d.class.getClassLoader();
        String property = System.getProperty("slf4j.provider");
        org.slf4j.spi.a aVar = null;
        if (property != null && !property.isEmpty()) {
            try {
                String str = "Attempting to load provider \"" + property + "\" specified via \"slf4j.provider\" system property";
                int i = g.a;
                if (AbstractC0147y.k(2) >= AbstractC0147y.k(g.b)) {
                    g.b().println("SLF4J(I): " + str);
                }
                aVar = (org.slf4j.spi.a) classLoader.loadClass(property).getConstructor(null).newInstance(null);
            } catch (ClassCastException e2) {
                g.a("Specified SLF4JServiceProvider (" + property + ") does not implement SLF4JServiceProvider interface", e2);
            } catch (ClassNotFoundException e3) {
                e = e3;
                g.a("Failed to instantiate the specified SLF4JServiceProvider (" + property + ")", e);
            } catch (IllegalAccessException e4) {
                e = e4;
                g.a("Failed to instantiate the specified SLF4JServiceProvider (" + property + ")", e);
            } catch (InstantiationException e5) {
                e = e5;
                g.a("Failed to instantiate the specified SLF4JServiceProvider (" + property + ")", e);
            } catch (NoSuchMethodException e6) {
                e = e6;
                g.a("Failed to instantiate the specified SLF4JServiceProvider (" + property + ")", e);
            } catch (InvocationTargetException e7) {
                e = e7;
                g.a("Failed to instantiate the specified SLF4JServiceProvider (" + property + ")", e);
            }
        }
        if (aVar != null) {
            arrayList.add(aVar);
            return arrayList;
        }
        Iterator it2 = (System.getSecurityManager() == null ? ServiceLoader.load(org.slf4j.spi.a.class, classLoader) : (ServiceLoader) AccessController.doPrivileged(new PrivilegedAction() { // from class: org.slf4j.c
            @Override // java.security.PrivilegedAction
            public final Object run() {
                return ServiceLoader.load(org.slf4j.spi.a.class, classLoader);
            }
        })).iterator();
        while (it2.hasNext()) {
            try {
                arrayList.add((org.slf4j.spi.a) it2.next());
            } catch (ServiceConfigurationError e8) {
                String str2 = "A service provider failed to instantiate:\n" + e8.getMessage();
                g.b().println("SLF4J(E): " + str2);
            }
        }
        return arrayList;
    }

    public static a b() {
        org.slf4j.spi.a aVar;
        if (a == 0) {
            synchronized (d.class) {
                try {
                    if (a == 0) {
                        a = 1;
                        e();
                    }
                } finally {
                }
            }
        }
        int i = a;
        if (i == 1) {
            aVar = b;
        } else {
            if (i == 2) {
                throw new IllegalStateException("org.slf4j.LoggerFactory in failed state. Original exception was thrown EARLIER. See also https://www.slf4j.org/codes.html#unsuccessfulInit");
            }
            if (i == 3) {
                aVar = e;
            } else {
                if (i != 4) {
                    throw new IllegalStateException("Unreachable code");
                }
                aVar = c;
            }
        }
        return aVar.a();
    }

    public static b c() {
        int i;
        b bVarD = d(com.fasterxml.uuid.c.class.getName());
        if (d) {
            j jVar = k.a;
            Class cls = null;
            if (jVar == null) {
                if (k.b) {
                    jVar = null;
                } else {
                    try {
                        jVar = new j();
                    } catch (SecurityException unused) {
                        jVar = null;
                    }
                    k.a = jVar;
                    k.b = true;
                }
            }
            if (jVar != null) {
                Class[] classContext = jVar.getClassContext();
                String name = k.class.getName();
                int i2 = 0;
                while (i2 < classContext.length && !name.equals(classContext[i2].getName())) {
                    i2++;
                }
                if (i2 >= classContext.length || (i = i2 + 2) >= classContext.length) {
                    throw new IllegalStateException("Failed to find org.slf4j.helpers.Util or its caller in the stack; this should not happen");
                }
                cls = classContext[i];
            }
            if (cls != null && !cls.isAssignableFrom(com.fasterxml.uuid.c.class)) {
                g.c("Detected logger name mismatch. Given name: \"" + bVarD.getName() + "\"; computed name: \"" + cls.getName() + "\".");
                g.c("See https://www.slf4j.org/codes.html#loggerNameMismatch for an explanation");
            }
        }
        return bVarD;
    }

    public static b d(String str) {
        return b().a(str);
    }

    public static final void e() {
        try {
            ArrayList arrayListA = a();
            i(arrayListA);
            if (arrayListA.isEmpty()) {
                a = 4;
                g.c("No SLF4J providers were found.");
                g.c("Defaulting to no-operation (NOP) logger implementation");
                g.c("See https://www.slf4j.org/codes.html#noProviders for further details.");
                LinkedHashSet linkedHashSet = new LinkedHashSet();
                try {
                    ClassLoader classLoader = d.class.getClassLoader();
                    Enumeration<URL> systemResources = classLoader == null ? ClassLoader.getSystemResources("org/slf4j/impl/StaticLoggerBinder.class") : classLoader.getResources("org/slf4j/impl/StaticLoggerBinder.class");
                    while (systemResources.hasMoreElements()) {
                        linkedHashSet.add(systemResources.nextElement());
                    }
                } catch (IOException e2) {
                    g.a("Error getting resources from path", e2);
                }
                h(linkedHashSet);
            } else {
                e = (org.slf4j.spi.a) arrayListA.get(0);
                e.getClass();
                e.getClass();
                a = 3;
                g(arrayListA);
            }
            f();
            if (a == 3) {
                try {
                    String strB = e.b();
                    boolean z = false;
                    for (String str : f) {
                        if (strB.startsWith(str)) {
                            z = true;
                        }
                    }
                    if (z) {
                        return;
                    }
                    g.c("The requested version " + strB + " by your slf4j provider is not compatible with " + Arrays.asList(f).toString());
                    g.c("See https://www.slf4j.org/codes.html#version_mismatch for further details.");
                } catch (Throwable th) {
                    g.a("Unexpected problem occurred during version sanity check", th);
                }
            }
        } catch (Exception e3) {
            a = 2;
            g.a("Failed to instantiate SLF4J LoggerFactory", e3);
            throw new IllegalStateException("Unexpected initialization failure", e3);
        }
    }

    public static void f() throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        e eVar = b;
        synchronized (eVar) {
            try {
                ((i) eVar.b).a = true;
                i iVar = (i) eVar.b;
                iVar.getClass();
                Iterator it2 = new ArrayList(iVar.b.values()).iterator();
                while (it2.hasNext()) {
                    h hVar = (h) it2.next();
                    hVar.b = d(hVar.a);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        LinkedBlockingQueue linkedBlockingQueue = ((i) b.b).c;
        int size = linkedBlockingQueue.size();
        ArrayList arrayList = new ArrayList(128);
        int i = 0;
        while (linkedBlockingQueue.drainTo(arrayList, 128) != 0) {
            Iterator it3 = arrayList.iterator();
            while (it3.hasNext()) {
                org.slf4j.event.b bVar = (org.slf4j.event.b) it3.next();
                if (bVar != null) {
                    h hVar2 = bVar.b;
                    String str = hVar2.a;
                    if (hVar2.b == null) {
                        throw new IllegalStateException("Delegate logger cannot be null at this state.");
                    }
                    if (!(hVar2.b instanceof org.slf4j.helpers.c)) {
                        if (!hVar2.q()) {
                            g.c(str);
                        } else if (hVar2.o(bVar.a) && hVar2.q()) {
                            try {
                                hVar2.d.invoke(hVar2.b, bVar);
                            } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException unused) {
                            }
                        }
                    }
                }
                int i2 = i + 1;
                if (i == 0) {
                    if (bVar.b.q()) {
                        g.c("A number (" + size + ") of logging calls during the initialization phase have been intercepted and are");
                        g.c("now being replayed. These are subject to the filtering rules of the underlying logging system.");
                        g.c("See also https://www.slf4j.org/codes.html#replay");
                    } else if (!(bVar.b.b instanceof org.slf4j.helpers.c)) {
                        g.c("The following set of substitute loggers may have been accessed");
                        g.c("during the initialization phase. Logging calls during this");
                        g.c("phase were not honored. However, subsequent logging calls to these");
                        g.c("loggers will work as normally expected.");
                        g.c("See also https://www.slf4j.org/codes.html#substituteLogger");
                    }
                }
                i = i2;
            }
            arrayList.clear();
        }
        i iVar2 = (i) b.b;
        iVar2.b.clear();
        iVar2.c.clear();
    }

    public static void g(ArrayList arrayList) {
        if (arrayList.isEmpty()) {
            throw new IllegalStateException("No providers were found which is impossible after successful initialization.");
        }
        if (arrayList.size() > 1) {
            String str = "Actual provider is of type [" + arrayList.get(0) + "]";
            int i = g.a;
            if (AbstractC0147y.k(2) >= AbstractC0147y.k(g.b)) {
                g.b().println("SLF4J(I): " + str);
                return;
            }
            return;
        }
        String str2 = "Connected with provider of type [" + ((org.slf4j.spi.a) arrayList.get(0)).getClass().getName() + "]";
        int i2 = g.a;
        if (AbstractC0147y.k(1) >= AbstractC0147y.k(g.b)) {
            g.b().println("SLF4J(D): " + str2);
        }
    }

    public static void h(LinkedHashSet linkedHashSet) {
        if (linkedHashSet.isEmpty()) {
            return;
        }
        g.c("Class path contains SLF4J bindings targeting slf4j-api versions 1.7.x or earlier.");
        Iterator it2 = linkedHashSet.iterator();
        while (it2.hasNext()) {
            g.c("Ignoring binding found at [" + ((URL) it2.next()) + "]");
        }
        g.c("See https://www.slf4j.org/codes.html#ignoredBindings for an explanation.");
    }

    public static void i(ArrayList arrayList) {
        if (arrayList.size() > 1) {
            g.c("Class path contains multiple SLF4J providers.");
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                g.c("Found provider [" + ((org.slf4j.spi.a) it2.next()) + "]");
            }
            g.c("See https://www.slf4j.org/codes.html#multiple_bindings for an explanation.");
        }
    }
}

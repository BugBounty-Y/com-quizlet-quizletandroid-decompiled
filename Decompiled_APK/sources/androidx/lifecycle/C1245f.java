package androidx.lifecycle;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

/* renamed from: androidx.lifecycle.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1245f {
    public static final C1245f c = new C1245f();
    public final HashMap a = new HashMap();
    public final HashMap b = new HashMap();

    public static void b(HashMap map, C1244e c1244e, A a, Class cls) {
        A a2 = (A) map.get(c1244e);
        if (a2 == null || a == a2) {
            if (a2 == null) {
                map.put(c1244e, a);
                return;
            }
            return;
        }
        throw new IllegalArgumentException("Method " + c1244e.b.getName() + " in " + cls.getName() + " already declared with different @OnLifecycleEvent value: previous value " + a2 + ", new value " + a);
    }

    public final C1243d a(Class cls, Method[] methodArr) throws SecurityException {
        int i;
        Class superclass = cls.getSuperclass();
        HashMap map = new HashMap();
        HashMap map2 = this.a;
        if (superclass != null) {
            C1243d c1243dA = (C1243d) map2.get(superclass);
            if (c1243dA == null) {
                c1243dA = a(superclass, null);
            }
            map.putAll(c1243dA.b);
        }
        for (Class<?> cls2 : cls.getInterfaces()) {
            C1243d c1243dA2 = (C1243d) map2.get(cls2);
            if (c1243dA2 == null) {
                c1243dA2 = a(cls2, null);
            }
            for (Map.Entry entry : c1243dA2.b.entrySet()) {
                b(map, (C1244e) entry.getKey(), (A) entry.getValue(), cls);
            }
        }
        if (methodArr == null) {
            try {
                methodArr = cls.getDeclaredMethods();
            } catch (NoClassDefFoundError e) {
                throw new IllegalArgumentException("The observer class has some methods that use newer APIs which are not available in the current OS version. Lifecycles cannot access even other methods so you should make sure that your observer classes only access framework classes that are available in your min API level OR use lifecycle:compiler annotation processor.", e);
            }
        }
        boolean z = false;
        for (Method method : methodArr) {
            InterfaceC1238a0 interfaceC1238a0 = (InterfaceC1238a0) method.getAnnotation(InterfaceC1238a0.class);
            if (interfaceC1238a0 != null) {
                Class<?>[] parameterTypes = method.getParameterTypes();
                if (parameterTypes.length <= 0) {
                    i = 0;
                } else {
                    if (!J.class.isAssignableFrom(parameterTypes[0])) {
                        throw new IllegalArgumentException("invalid parameter type. Must be one and instanceof LifecycleOwner");
                    }
                    i = 1;
                }
                A aValue = interfaceC1238a0.value();
                if (parameterTypes.length > 1) {
                    if (!A.class.isAssignableFrom(parameterTypes[1])) {
                        throw new IllegalArgumentException("invalid parameter type. second arg must be an event");
                    }
                    if (aValue != A.ON_ANY) {
                        throw new IllegalArgumentException("Second arg is supported only for ON_ANY value");
                    }
                    i = 2;
                }
                if (parameterTypes.length > 2) {
                    throw new IllegalArgumentException("cannot have more than 2 params");
                }
                b(map, new C1244e(method, i), aValue, cls);
                z = true;
            }
        }
        C1243d c1243d = new C1243d(map);
        map2.put(cls, c1243d);
        this.b.put(cls, Boolean.valueOf(z));
        return c1243d;
    }
}

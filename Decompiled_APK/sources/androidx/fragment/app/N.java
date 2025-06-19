package androidx.fragment.app;

import androidx.fragment.app.Fragment;

/* loaded from: classes.dex */
public abstract class N {
    public static final androidx.collection.V a = new androidx.collection.V(0);

    public static Class b(ClassLoader classLoader, String str) throws ClassNotFoundException {
        androidx.collection.V v = a;
        androidx.collection.V v2 = (androidx.collection.V) v.get(classLoader);
        if (v2 == null) {
            v2 = new androidx.collection.V(0);
            v.put(classLoader, v2);
        }
        Class cls = (Class) v2.get(str);
        if (cls != null) {
            return cls;
        }
        Class<?> cls2 = Class.forName(str, false, classLoader);
        v2.put(str, cls2);
        return cls2;
    }

    public static Class c(ClassLoader classLoader, String str) {
        try {
            return b(classLoader, str);
        } catch (ClassCastException e) {
            throw new Fragment.InstantiationException(android.support.v4.media.session.a.B("Unable to instantiate fragment ", str, ": make sure class is a valid subclass of Fragment"), e);
        } catch (ClassNotFoundException e2) {
            throw new Fragment.InstantiationException(android.support.v4.media.session.a.B("Unable to instantiate fragment ", str, ": make sure class name exists"), e2);
        }
    }

    public abstract Fragment a(String str);
}

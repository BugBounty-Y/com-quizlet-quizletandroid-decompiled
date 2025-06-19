package com.squareup.otto;

import android.os.Looper;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/* loaded from: classes3.dex */
public final class g {
    public static final g a = new g();
    public static final g b = new g();

    public void a(c cVar) {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            return;
        }
        throw new IllegalStateException("Event bus " + cVar + " accessed from non-main thread " + Looper.myLooper());
    }

    public HashMap b(Object obj) throws SecurityException {
        ConcurrentHashMap concurrentHashMap = a.a;
        Class<?> cls = obj.getClass();
        HashMap map = new HashMap();
        Map map2 = (Map) a.a.get(cls);
        Map map3 = map2;
        if (map2 == null) {
            HashMap map4 = new HashMap();
            a.a(cls, map4, new HashMap());
            map3 = map4;
        }
        if (!map3.isEmpty()) {
            for (Map.Entry entry : map3.entrySet()) {
                map.put(entry.getKey(), new f(obj, (Method) entry.getValue()));
            }
        }
        return map;
    }

    public HashMap c(Object obj) throws SecurityException {
        ConcurrentHashMap concurrentHashMap = a.a;
        Class<?> cls = obj.getClass();
        HashMap map = new HashMap();
        Map map2 = (Map) a.b.get(cls);
        Map map3 = map2;
        if (map2 == null) {
            HashMap map4 = new HashMap();
            a.a(cls, new HashMap(), map4);
            map3 = map4;
        }
        if (!map3.isEmpty()) {
            for (Map.Entry entry : map3.entrySet()) {
                HashSet hashSet = new HashSet();
                Iterator it2 = ((Set) entry.getValue()).iterator();
                while (it2.hasNext()) {
                    hashSet.add(new e(obj, (Method) it2.next()));
                }
                map.put(entry.getKey(), hashSet);
            }
        }
        return map;
    }
}

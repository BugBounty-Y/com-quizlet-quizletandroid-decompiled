package androidx.lifecycle;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/* renamed from: androidx.lifecycle.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1243d {
    public final HashMap a = new HashMap();
    public final HashMap b;

    public C1243d(HashMap map) {
        this.b = map;
        for (Map.Entry entry : map.entrySet()) {
            A a = (A) entry.getValue();
            List arrayList = (List) this.a.get(a);
            if (arrayList == null) {
                arrayList = new ArrayList();
                this.a.put(a, arrayList);
            }
            arrayList.add((C1244e) entry.getKey());
        }
    }

    public static void a(List list, J j, A a, I i) throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        if (list != null) {
            for (int size = list.size() - 1; size >= 0; size--) {
                C1244e c1244e = (C1244e) list.get(size);
                c1244e.getClass();
                try {
                    int i2 = c1244e.a;
                    Method method = c1244e.b;
                    if (i2 == 0) {
                        method.invoke(i, null);
                    } else if (i2 == 1) {
                        method.invoke(i, j);
                    } else if (i2 == 2) {
                        method.invoke(i, j, a);
                    }
                } catch (IllegalAccessException e) {
                    throw new RuntimeException(e);
                } catch (InvocationTargetException e2) {
                    throw new RuntimeException("Failed to call observer method", e2.getCause());
                }
            }
        }
    }
}

package androidx.datastore.preferences.protobuf;

import java.util.Collections;
import java.util.Map;

/* renamed from: androidx.datastore.preferences.protobuf.m, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1106m {
    public static volatile C1106m a;
    public static final C1106m b;

    static {
        C1106m c1106m = new C1106m();
        Map map = Collections.EMPTY_MAP;
        b = c1106m;
    }

    public static C1106m a() {
        C1106m c1106m;
        Q q = Q.c;
        C1106m c1106m2 = a;
        if (c1106m2 != null) {
            return c1106m2;
        }
        synchronized (C1106m.class) {
            try {
                c1106m = a;
                if (c1106m == null) {
                    Class cls = AbstractC1105l.a;
                    C1106m c1106m3 = null;
                    if (cls != null) {
                        try {
                            c1106m3 = (C1106m) cls.getDeclaredMethod("getEmptyRegistry", null).invoke(null, null);
                        } catch (Exception unused) {
                        }
                    }
                    c1106m = c1106m3 != null ? c1106m3 : b;
                    a = c1106m;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return c1106m;
    }
}

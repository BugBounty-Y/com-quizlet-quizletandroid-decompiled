package androidx.glance.appwidget.protobuf;

import java.util.Collections;
import java.util.Map;

/* renamed from: androidx.glance.appwidget.protobuf.l, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1200l {
    public static volatile C1200l a;
    public static final C1200l b;

    static {
        C1200l c1200l = new C1200l();
        Map map = Collections.EMPTY_MAP;
        b = c1200l;
    }

    public static C1200l a() {
        C1200l c1200l;
        L l = L.c;
        C1200l c1200l2 = a;
        if (c1200l2 != null) {
            return c1200l2;
        }
        synchronized (C1200l.class) {
            try {
                c1200l = a;
                if (c1200l == null) {
                    Class cls = AbstractC1199k.a;
                    C1200l c1200l3 = null;
                    if (cls != null) {
                        try {
                            c1200l3 = (C1200l) cls.getDeclaredMethod("getEmptyRegistry", null).invoke(null, null);
                        } catch (Exception unused) {
                        }
                    }
                    c1200l = c1200l3 != null ? c1200l3 : b;
                    a = c1200l;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return c1200l;
    }
}

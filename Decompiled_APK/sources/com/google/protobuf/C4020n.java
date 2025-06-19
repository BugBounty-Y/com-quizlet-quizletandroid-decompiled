package com.google.protobuf;

import java.util.Collections;
import java.util.Map;

/* renamed from: com.google.protobuf.n, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4020n {
    public static volatile C4020n a;
    public static final C4020n b;

    static {
        C4020n c4020n = new C4020n();
        Map map = Collections.EMPTY_MAP;
        b = c4020n;
    }

    public static C4020n a() {
        C4020n c4020n;
        C4020n c4020n2 = a;
        if (c4020n2 != null) {
            return c4020n2;
        }
        synchronized (C4020n.class) {
            try {
                c4020n = a;
                if (c4020n == null) {
                    Class cls = AbstractC4019m.a;
                    C4020n c4020n3 = null;
                    if (cls != null) {
                        try {
                            c4020n3 = (C4020n) cls.getDeclaredMethod("getEmptyRegistry", null).invoke(null, null);
                        } catch (Exception unused) {
                        }
                    }
                    c4020n = c4020n3 != null ? c4020n3 : b;
                    a = c4020n;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return c4020n;
    }
}

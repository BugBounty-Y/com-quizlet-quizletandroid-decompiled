package com.google.android.gms.internal.ads;

import java.util.Collections;
import java.util.Map;

/* loaded from: classes2.dex */
public final class IA {
    public static volatile IA a;
    public static final IA b;

    static {
        IA ia = new IA();
        Map map = Collections.EMPTY_MAP;
        b = ia;
    }

    public static IA a() {
        C2305lB c2305lB = C2305lB.c;
        return b;
    }

    public static IA b() {
        IA ia = a;
        if (ia != null) {
            return ia;
        }
        synchronized (IA.class) {
            try {
                IA ia2 = a;
                if (ia2 != null) {
                    return ia2;
                }
                C2305lB c2305lB = C2305lB.c;
                IA iaQ = LA.q();
                a = iaQ;
                return iaQ;
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}

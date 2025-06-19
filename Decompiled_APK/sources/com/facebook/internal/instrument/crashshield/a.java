package com.facebook.internal.instrument.crashshield;

import com.facebook.B;
import com.facebook.o;
import com.google.android.gms.internal.mlkit_vision_common.E2;
import com.google.android.gms.internal.mlkit_vision_common.F2;
import java.util.Collections;
import java.util.Set;
import java.util.WeakHashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class a {
    public static final Set a = Collections.newSetFromMap(new WeakHashMap());
    public static boolean b;

    public static final void a(Object o, Throwable th) {
        Intrinsics.checkNotNullParameter(o, "o");
        if (b) {
            a.add(o);
            o oVar = o.a;
            if (B.c()) {
                E2.b(th);
                F2.c(th, com.facebook.internal.instrument.a.e).b();
            }
        }
    }

    public static final boolean b(Object o) {
        Intrinsics.checkNotNullParameter(o, "o");
        return a.contains(o);
    }
}

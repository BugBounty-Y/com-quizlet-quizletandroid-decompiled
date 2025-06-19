package androidx.work;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class U {
    public static final String a;

    static {
        String strE = z.e("WorkerFactory");
        Intrinsics.checkNotNullExpressionValue(strE, "tagWithPrefix(\"WorkerFactory\")");
        a = strE;
    }
}

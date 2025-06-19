package androidx.work.impl;

import java.util.concurrent.TimeUnit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class m {
    public static final String a;
    public static final long b;

    static {
        String strE = androidx.work.z.e("UnfinishedWorkListener");
        Intrinsics.checkNotNullExpressionValue(strE, "tagWithPrefix(\"UnfinishedWorkListener\")");
        a = strE;
        b = TimeUnit.HOURS.toMillis(1L);
    }
}

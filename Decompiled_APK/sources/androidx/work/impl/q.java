package androidx.work.impl;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class q {
    public static final String a;
    public static final String[] b;

    static {
        String strE = androidx.work.z.e("WrkDbPathHelper");
        Intrinsics.checkNotNullExpressionValue(strE, "tagWithPrefix(\"WrkDbPathHelper\")");
        a = strE;
        b = new String[]{"-journal", "-shm", "-wal"};
    }
}

package androidx.work.impl.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class u {
    public final String a;
    public final String b;

    public u(String tag, String workSpecId) {
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(workSpecId, "workSpecId");
        this.a = tag;
        this.b = workSpecId;
    }
}

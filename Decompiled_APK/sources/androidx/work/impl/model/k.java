package androidx.work.impl.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class k {
    public final String a;
    public final String b;

    public k(String name, String workSpecId) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(workSpecId, "workSpecId");
        this.a = name;
        this.b = workSpecId;
    }
}

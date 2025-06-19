package androidx.paging;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class K0 extends N0 {
    public final Object a;

    public K0(Object key) {
        Intrinsics.checkNotNullParameter(key, "key");
        this.a = key;
    }

    @Override // androidx.paging.N0
    public final Object a() {
        return this.a;
    }
}

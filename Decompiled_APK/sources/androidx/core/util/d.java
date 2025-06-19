package androidx.core.util;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class d extends androidx.constraintlayout.core.d {
    public final Object c;

    public d(int i) {
        super(i);
        this.c = new Object();
    }

    @Override // androidx.constraintlayout.core.d
    public final Object a() {
        Object objA;
        synchronized (this.c) {
            objA = super.a();
        }
        return objA;
    }

    @Override // androidx.constraintlayout.core.d
    public final boolean c(Object instance) {
        boolean zC;
        Intrinsics.checkNotNullParameter(instance, "instance");
        synchronized (this.c) {
            zC = super.c(instance);
        }
        return zC;
    }
}

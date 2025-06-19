package androidx.compose.animation.core;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.animation.core.m0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0255m0 implements InterfaceC0256n {
    public final D a;
    public final long b;

    public C0255m0(D d, long j) {
        this.a = d;
        this.b = j;
    }

    @Override // androidx.compose.animation.core.InterfaceC0256n
    public final N0 a(L0 l0) {
        return new C0257n0(this.a.a(l0), this.b);
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof C0255m0)) {
            return false;
        }
        C0255m0 c0255m0 = (C0255m0) obj;
        return c0255m0.b == this.b && Intrinsics.b(c0255m0.a, this.a);
    }

    public final int hashCode() {
        return Long.hashCode(this.b) + (this.a.hashCode() * 31);
    }
}

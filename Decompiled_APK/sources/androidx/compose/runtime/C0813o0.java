package androidx.compose.runtime;

import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.runtime.o0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0813o0 {
    public int a;
    public InterfaceC0815p0 b;
    public C0774b c;
    public Function2 d;
    public int e;
    public androidx.collection.C f;
    public androidx.collection.I g;

    public C0813o0(C0833w c0833w) {
        this.b = c0833w;
    }

    public static boolean a(E e, androidx.collection.I i) {
        Intrinsics.e(e, "null cannot be cast to non-null type androidx.compose.runtime.DerivedState<kotlin.Any?>");
        M0 m0 = e.c;
        if (m0 == null) {
            m0 = V.f;
        }
        return !m0.a(e.j().f, i.f(e));
    }

    public final boolean b() {
        if (this.b != null) {
            C0774b c0774b = this.c;
            if (c0774b != null ? c0774b.a() : false) {
                return true;
            }
        }
        return false;
    }

    public final P c(Object obj) {
        P pB;
        InterfaceC0815p0 interfaceC0815p0 = this.b;
        return (interfaceC0815p0 == null || (pB = interfaceC0815p0.b(this, obj)) == null) ? P.a : pB;
    }

    public final void d() {
        InterfaceC0815p0 interfaceC0815p0 = this.b;
        if (interfaceC0815p0 != null) {
            interfaceC0815p0.a();
        }
        this.b = null;
        this.f = null;
        this.g = null;
    }

    public final void e(boolean z) {
        if (z) {
            this.a |= 32;
        } else {
            this.a &= -33;
        }
    }
}

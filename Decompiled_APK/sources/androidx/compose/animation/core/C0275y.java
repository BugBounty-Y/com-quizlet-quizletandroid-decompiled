package androidx.compose.animation.core;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.animation.core.y, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0275y implements InterfaceC0250k {
    public final R0 a;
    public final L0 b;
    public final Object c;
    public final AbstractC0267t d;
    public final AbstractC0267t e;
    public final AbstractC0267t f;
    public final Object g;
    public final long h;

    public C0275y(C0276z c0276z, L0 l0, Object obj, AbstractC0267t abstractC0267t) {
        R0 r0 = new R0(c0276z.a);
        this.a = r0;
        this.b = l0;
        this.c = obj;
        AbstractC0267t abstractC0267t2 = (AbstractC0267t) l0.a.invoke(obj);
        this.d = abstractC0267t2;
        this.e = AbstractC0240f.k(abstractC0267t);
        if (r0.d == null) {
            r0.d = abstractC0267t2.c();
        }
        AbstractC0267t abstractC0267t3 = r0.d;
        if (abstractC0267t3 == null) {
            Intrinsics.m("targetVector");
            throw null;
        }
        int iB = abstractC0267t3.b();
        for (int i = 0; i < iB; i++) {
            AbstractC0267t abstractC0267t4 = r0.d;
            if (abstractC0267t4 == null) {
                Intrinsics.m("targetVector");
                throw null;
            }
            abstractC0267t4.e(r0.a.r(abstractC0267t2.a(i), abstractC0267t.a(i)), i);
        }
        AbstractC0267t abstractC0267t5 = r0.d;
        if (abstractC0267t5 == null) {
            Intrinsics.m("targetVector");
            throw null;
        }
        this.g = l0.b.invoke(abstractC0267t5);
        if (r0.c == null) {
            r0.c = abstractC0267t2.c();
        }
        AbstractC0267t abstractC0267t6 = r0.c;
        if (abstractC0267t6 == null) {
            Intrinsics.m("velocityVector");
            throw null;
        }
        int iB2 = abstractC0267t6.b();
        long jMax = 0;
        for (int i2 = 0; i2 < iB2; i2++) {
            abstractC0267t2.getClass();
            jMax = Math.max(jMax, r0.a.q(abstractC0267t.a(i2)));
        }
        this.h = jMax;
        AbstractC0267t abstractC0267tK = AbstractC0240f.k(this.a.a(jMax, this.d, abstractC0267t));
        this.f = abstractC0267tK;
        int iB3 = abstractC0267tK.b();
        for (int i3 = 0; i3 < iB3; i3++) {
            AbstractC0267t abstractC0267t7 = this.f;
            float fA = abstractC0267t7.a(i3);
            float f = this.a.e;
            abstractC0267t7.e(kotlin.ranges.l.b(fA, -f, f), i3);
        }
    }

    @Override // androidx.compose.animation.core.InterfaceC0250k
    public final boolean a() {
        return false;
    }

    @Override // androidx.compose.animation.core.InterfaceC0250k
    public final long b() {
        return this.h;
    }

    @Override // androidx.compose.animation.core.InterfaceC0250k
    public final L0 c() {
        return this.b;
    }

    @Override // androidx.compose.animation.core.InterfaceC0250k
    public final AbstractC0267t d(long j) {
        if (e(j)) {
            return this.f;
        }
        return this.a.a(j, this.d, this.e);
    }

    @Override // androidx.compose.animation.core.InterfaceC0250k
    public final Object f(long j) {
        if (e(j)) {
            return this.g;
        }
        Function1 function1 = this.b.b;
        R0 r0 = this.a;
        AbstractC0267t abstractC0267t = r0.b;
        AbstractC0267t abstractC0267t2 = this.d;
        if (abstractC0267t == null) {
            r0.b = abstractC0267t2.c();
        }
        AbstractC0267t abstractC0267t3 = r0.b;
        if (abstractC0267t3 == null) {
            Intrinsics.m("valueVector");
            throw null;
        }
        int iB = abstractC0267t3.b();
        for (int i = 0; i < iB; i++) {
            AbstractC0267t abstractC0267t4 = r0.b;
            if (abstractC0267t4 == null) {
                Intrinsics.m("valueVector");
                throw null;
            }
            abstractC0267t4.e(r0.a.n(abstractC0267t2.a(i), this.e.a(i), j), i);
        }
        AbstractC0267t abstractC0267t5 = r0.b;
        if (abstractC0267t5 != null) {
            return function1.invoke(abstractC0267t5);
        }
        Intrinsics.m("valueVector");
        throw null;
    }

    @Override // androidx.compose.animation.core.InterfaceC0250k
    public final Object g() {
        return this.g;
    }
}

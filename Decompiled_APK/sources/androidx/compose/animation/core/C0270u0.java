package androidx.compose.animation.core;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.animation.core.u0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0270u0 implements InterfaceC0250k {
    public final N0 a;
    public final L0 b;
    public Object c;
    public Object d;
    public AbstractC0267t e;
    public AbstractC0267t f;
    public final AbstractC0267t g;
    public long h;
    public AbstractC0267t i;

    public C0270u0(InterfaceC0256n interfaceC0256n, L0 l0, Object obj, Object obj2, AbstractC0267t abstractC0267t) {
        this.a = interfaceC0256n.a(l0);
        this.b = l0;
        this.c = obj2;
        this.d = obj;
        this.e = (AbstractC0267t) l0.a.invoke(obj);
        Function1 function1 = l0.a;
        this.f = (AbstractC0267t) function1.invoke(obj2);
        this.g = abstractC0267t != null ? AbstractC0240f.k(abstractC0267t) : ((AbstractC0267t) function1.invoke(obj)).c();
        this.h = -1L;
    }

    @Override // androidx.compose.animation.core.InterfaceC0250k
    public final boolean a() {
        return this.a.a();
    }

    @Override // androidx.compose.animation.core.InterfaceC0250k
    public final long b() {
        if (this.h < 0) {
            this.h = this.a.b(this.e, this.f, this.g);
        }
        return this.h;
    }

    @Override // androidx.compose.animation.core.InterfaceC0250k
    public final L0 c() {
        return this.b;
    }

    @Override // androidx.compose.animation.core.InterfaceC0250k
    public final AbstractC0267t d(long j) {
        if (!e(j)) {
            return this.a.j(j, this.e, this.f, this.g);
        }
        AbstractC0267t abstractC0267t = this.i;
        if (abstractC0267t != null) {
            return abstractC0267t;
        }
        AbstractC0267t abstractC0267tN = this.a.n(this.e, this.f, this.g);
        this.i = abstractC0267tN;
        return abstractC0267tN;
    }

    @Override // androidx.compose.animation.core.InterfaceC0250k
    public final Object f(long j) {
        if (e(j)) {
            return this.c;
        }
        AbstractC0267t abstractC0267tT = this.a.t(j, this.e, this.f, this.g);
        int iB = abstractC0267tT.b();
        for (int i = 0; i < iB; i++) {
            if (Float.isNaN(abstractC0267tT.a(i))) {
                throw new IllegalStateException("AnimationVector cannot contain a NaN. " + abstractC0267tT + ". Animation: " + this + ", playTimeNanos: " + j);
            }
        }
        return this.b.b.invoke(abstractC0267tT);
    }

    @Override // androidx.compose.animation.core.InterfaceC0250k
    public final Object g() {
        return this.c;
    }

    public final void h(Object obj) {
        if (Intrinsics.b(obj, this.d)) {
            return;
        }
        this.d = obj;
        this.e = (AbstractC0267t) this.b.a.invoke(obj);
        this.i = null;
        this.h = -1L;
    }

    public final void i(Object obj) {
        if (Intrinsics.b(this.c, obj)) {
            return;
        }
        this.c = obj;
        this.f = (AbstractC0267t) this.b.a.invoke(obj);
        this.i = null;
        this.h = -1L;
    }

    public final String toString() {
        return "TargetBasedAnimation: " + this.d + " -> " + this.c + ",initial velocity: " + this.g + ", duration: " + (b() / 1000000) + " ms,animationSpec: " + this.a;
    }
}

package androidx.compose.animation.core;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.navigation.C1291m;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5028l;

/* renamed from: androidx.compose.animation.core.i0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0247i0 extends J0 {
    public static final C0260p s = new C0260p(DefinitionKt.NO_Float_VALUE);
    public static final C0260p t = new C0260p(1.0f);
    public final InterfaceC0773a0 c;
    public final InterfaceC0773a0 d;
    public Object e;
    public E0 f;
    public long g;
    public final K h;
    public final androidx.compose.runtime.F0 i;
    public C5028l j;
    public final kotlinx.coroutines.sync.c k;
    public final W l;
    public long m;
    public final androidx.collection.G n;
    public X o;
    public final Y p;
    public float q;
    public final Y r;

    public C0247i0(C1291m c1291m) {
        super(0);
        this.c = C0776c.z(c1291m);
        this.d = C0776c.z(c1291m);
        this.e = c1291m;
        this.h = new K(this, 1);
        this.i = C0776c.v(DefinitionKt.NO_Float_VALUE);
        this.k = kotlinx.coroutines.sync.d.a();
        this.l = new W();
        this.m = Long.MIN_VALUE;
        this.n = new androidx.collection.G();
        this.p = new Y(this, 1);
        this.r = new Y(this, 0);
    }

    public static final void T(C0247i0 c0247i0) {
        E0 e0 = c0247i0.f;
        if (e0 == null) {
            return;
        }
        X x = c0247i0.o;
        if (x == null) {
            if (c0247i0.g <= 0 || c0247i0.a0() == 1.0f || Intrinsics.b(((androidx.compose.runtime.L0) c0247i0.d).getValue(), ((androidx.compose.runtime.L0) c0247i0.c).getValue())) {
                x = null;
            } else {
                x = new X();
                x.d = c0247i0.a0();
                long j = c0247i0.g;
                x.g = j;
                x.h = kotlin.math.c.c((1.0d - c0247i0.a0()) * j);
                x.e.e(c0247i0.a0(), 0);
            }
        }
        if (x != null) {
            x.g = c0247i0.g;
            c0247i0.n.a(x);
            e0.o(x);
        }
        c0247i0.o = null;
    }

    public static final void U(C0247i0 c0247i0, X x, long j) {
        c0247i0.getClass();
        long j2 = x.a + j;
        x.a = j2;
        long j3 = x.h;
        if (j2 >= j3) {
            x.d = 1.0f;
            return;
        }
        Q0 q0 = x.b;
        if (q0 == null) {
            float fA = x.e.a(0);
            float f = j2 / j3;
            L0 l0 = M0.a;
            x.d = (1.0f * f) + ((1 - f) * fA);
            return;
        }
        C0260p c0260p = t;
        C0260p c0260p2 = x.f;
        if (c0260p2 == null) {
            c0260p2 = s;
        }
        x.d = kotlin.ranges.l.b(((C0260p) q0.t(j2, x.e, c0260p, c0260p2)).a(0), DefinitionKt.NO_Float_VALUE, 1.0f);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object V(androidx.compose.animation.core.C0247i0 r9, kotlin.coroutines.jvm.internal.c r10) {
        /*
            r9.getClass()
            boolean r0 = r10 instanceof androidx.compose.animation.core.C0233b0
            if (r0 == 0) goto L16
            r0 = r10
            androidx.compose.animation.core.b0 r0 = (androidx.compose.animation.core.C0233b0) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.m = r1
            goto L1b
        L16:
            androidx.compose.animation.core.b0 r0 = new androidx.compose.animation.core.b0
            r0.<init>(r9, r10)
        L1b:
            java.lang.Object r10 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 2
            r4 = 1
            r5 = -9223372036854775808
            if (r2 == 0) goto L3a
            if (r2 == r4) goto L34
            if (r2 != r3) goto L2c
            goto L34
        L2c:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r10 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r10)
            throw r9
        L34:
            androidx.compose.animation.core.i0 r9 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L7c
        L3a:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            androidx.collection.G r10 = r9.n
            boolean r10 = r10.e()
            if (r10 == 0) goto L4c
            androidx.compose.animation.core.X r10 = r9.o
            if (r10 != 0) goto L4c
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        L4c:
            kotlin.coroutines.CoroutineContext r10 = r0.getContext()
            float r10 = androidx.compose.animation.core.AbstractC0240f.n(r10)
            r2 = 0
            int r10 = (r10 > r2 ? 1 : (r10 == r2 ? 0 : -1))
            if (r10 != 0) goto L61
            r9.Z()
            r9.m = r5
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        L61:
            long r7 = r9.m
            int r10 = (r7 > r5 ? 1 : (r7 == r5 ? 0 : -1))
            if (r10 != 0) goto L7c
            r0.j = r9
            r0.m = r4
            kotlin.coroutines.CoroutineContext r10 = r0.getContext()
            androidx.compose.runtime.W r10 = androidx.compose.runtime.C0776c.r(r10)
            androidx.compose.animation.core.Y r2 = r9.p
            java.lang.Object r10 = r10.P(r2, r0)
            if (r10 != r1) goto L7c
            goto L91
        L7c:
            androidx.collection.G r10 = r9.n
            int r10 = r10.b
            if (r10 == 0) goto L83
            goto L87
        L83:
            androidx.compose.animation.core.X r10 = r9.o
            if (r10 == 0) goto L92
        L87:
            r0.j = r9
            r0.m = r3
            java.lang.Object r10 = r9.Y(r0)
            if (r10 != r1) goto L7c
        L91:
            return r1
        L92:
            r9.m = r5
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.animation.core.C0247i0.V(androidx.compose.animation.core.i0, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:27:0x008e  */
    /* JADX WARN: Removed duplicated region for block: B:29:0x0091  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object W(androidx.compose.animation.core.C0247i0 r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r5.getClass()
            boolean r0 = r6 instanceof androidx.compose.animation.core.C0243g0
            if (r0 == 0) goto L16
            r0 = r6
            androidx.compose.animation.core.g0 r0 = (androidx.compose.animation.core.C0243g0) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.n = r1
            goto L1b
        L16:
            androidx.compose.animation.core.g0 r0 = new androidx.compose.animation.core.g0
            r0.<init>(r5, r6)
        L1b:
            java.lang.Object r6 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L43
            if (r2 == r4) goto L39
            if (r2 != r3) goto L31
            java.lang.Object r5 = r0.k
            androidx.compose.animation.core.i0 r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L88
        L31:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L39:
            java.lang.Object r5 = r0.k
            androidx.compose.animation.core.i0 r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r6 = r5
            r5 = r2
            goto L5d
        L43:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            androidx.compose.runtime.a0 r6 = r5.c
            androidx.compose.runtime.L0 r6 = (androidx.compose.runtime.L0) r6
            java.lang.Object r6 = r6.getValue()
            r0.j = r5
            r0.k = r6
            r0.n = r4
            kotlinx.coroutines.sync.c r2 = r5.k
            java.lang.Object r2 = r2.d(r0)
            if (r2 != r1) goto L5d
            goto L84
        L5d:
            r0.j = r5
            r0.k = r6
            r0.n = r3
            kotlinx.coroutines.l r2 = new kotlinx.coroutines.l
            kotlin.coroutines.h r3 = kotlin.coroutines.intrinsics.h.b(r0)
            r2.<init>(r4, r3)
            r2.r()
            r5.j = r2
            r3 = 0
            kotlinx.coroutines.sync.c r4 = r5.k
            r4.f(r3)
            java.lang.Object r2 = r2.q()
            if (r2 != r1) goto L82
            java.lang.String r3 = "frame"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r3)
        L82:
            if (r2 != r1) goto L85
        L84:
            return r1
        L85:
            r0 = r5
            r5 = r6
            r6 = r2
        L88:
            boolean r5 = kotlin.jvm.internal.Intrinsics.b(r6, r5)
            if (r5 == 0) goto L91
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        L91:
            r5 = -9223372036854775808
            r0.m = r5
            java.util.concurrent.CancellationException r5 = new java.util.concurrent.CancellationException
            java.lang.String r6 = "targetState while waiting for composition"
            r5.<init>(r6)
            throw r5
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.animation.core.C0247i0.W(androidx.compose.animation.core.i0, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:33:0x009b  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object X(androidx.compose.animation.core.C0247i0 r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r7.getClass()
            boolean r0 = r8 instanceof androidx.compose.animation.core.C0245h0
            if (r0 == 0) goto L16
            r0 = r8
            androidx.compose.animation.core.h0 r0 = (androidx.compose.animation.core.C0245h0) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.n = r1
            goto L1b
        L16:
            androidx.compose.animation.core.h0 r0 = new androidx.compose.animation.core.h0
            r0.<init>(r7, r8)
        L1b:
            java.lang.Object r8 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L41
            if (r2 == r4) goto L39
            if (r2 != r3) goto L31
            java.lang.Object r7 = r0.k
            androidx.compose.animation.core.i0 r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L92
        L31:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L39:
            java.lang.Object r7 = r0.k
            androidx.compose.animation.core.i0 r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L5d
        L41:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            androidx.compose.runtime.a0 r8 = r7.c
            androidx.compose.runtime.L0 r8 = (androidx.compose.runtime.L0) r8
            java.lang.Object r8 = r8.getValue()
            r0.j = r7
            r0.k = r8
            r0.n = r4
            kotlinx.coroutines.sync.c r2 = r7.k
            java.lang.Object r2 = r2.d(r0)
            if (r2 != r1) goto L5b
            goto L90
        L5b:
            r2 = r7
            r7 = r8
        L5d:
            java.lang.Object r8 = r2.e
            boolean r8 = kotlin.jvm.internal.Intrinsics.b(r7, r8)
            r5 = 0
            kotlinx.coroutines.sync.c r6 = r2.k
            if (r8 == 0) goto L6c
            r6.f(r5)
            goto L98
        L6c:
            r0.j = r2
            r0.k = r7
            r0.n = r3
            kotlinx.coroutines.l r8 = new kotlinx.coroutines.l
            kotlin.coroutines.h r3 = kotlin.coroutines.intrinsics.h.b(r0)
            r8.<init>(r4, r3)
            r8.r()
            r2.j = r8
            r6.f(r5)
            java.lang.Object r8 = r8.q()
            if (r8 != r1) goto L8e
            java.lang.String r3 = "frame"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r3)
        L8e:
            if (r8 != r1) goto L91
        L90:
            return r1
        L91:
            r0 = r2
        L92:
            boolean r1 = kotlin.jvm.internal.Intrinsics.b(r8, r7)
            if (r1 == 0) goto L9b
        L98:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        L9b:
            r1 = -9223372036854775808
            r0.m = r1
            java.util.concurrent.CancellationException r0 = new java.util.concurrent.CancellationException
            java.lang.StringBuilder r1 = new java.lang.StringBuilder
            java.lang.String r2 = "snapTo() was canceled because state was changed to "
            r1.<init>(r2)
            r1.append(r8)
            java.lang.String r8 = " instead of "
            r1.append(r8)
            r1.append(r7)
            java.lang.String r7 = r1.toString()
            r0.<init>(r7)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.animation.core.C0247i0.X(androidx.compose.animation.core.i0, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // androidx.compose.animation.core.J0
    public final Object I() {
        return ((androidx.compose.runtime.L0) this.c).getValue();
    }

    @Override // androidx.compose.animation.core.J0
    public final void L(Object obj) {
        ((androidx.compose.runtime.L0) this.d).setValue(obj);
    }

    @Override // androidx.compose.animation.core.J0
    public final void M(E0 e0) {
        E0 e02 = this.f;
        if (e02 == null || Intrinsics.b(e0, e02)) {
            this.f = e0;
            return;
        }
        throw new IllegalStateException("An instance of SeekableTransitionState has been used in different Transitions. Previous instance: " + this.f + ", new instance: " + e0);
    }

    /* JADX WARN: Type inference failed for: r0v1, types: [java.lang.Object, kotlin.k] */
    @Override // androidx.compose.animation.core.J0
    public final void N() throws Throwable {
        this.f = null;
        ((androidx.compose.runtime.snapshots.v) I0.a.getValue()).c(this);
    }

    public final Object Y(kotlin.coroutines.jvm.internal.c cVar) {
        float fN = AbstractC0240f.n(cVar.getContext());
        if (fN <= DefinitionKt.NO_Float_VALUE) {
            Z();
            return Unit.a;
        }
        this.q = fN;
        Object objP = C0776c.r(cVar.getContext()).P(this.r, cVar);
        return objP == kotlin.coroutines.intrinsics.a.a ? objP : Unit.a;
    }

    public final void Z() {
        E0 e0 = this.f;
        if (e0 != null) {
            e0.c();
        }
        androidx.collection.G g = this.n;
        C4930v.o(g.a, null, 0, g.b);
        g.b = 0;
        if (this.o != null) {
            this.o = null;
            d0(1.0f);
            c0();
        }
    }

    public final float a0() {
        return this.i.i();
    }

    public final Object b0(float f, Object obj, kotlin.coroutines.jvm.internal.i iVar) {
        if (DefinitionKt.NO_Float_VALUE > f || f > 1.0f) {
            throw new IllegalArgumentException("Expecting fraction between 0 and 1. Got " + f);
        }
        E0 e0 = this.f;
        if (e0 == null) {
            return Unit.a;
        }
        Object objA = W.a(this.l, new C0239e0(obj, ((androidx.compose.runtime.L0) this.c).getValue(), this, e0, f, null), iVar);
        return objA == kotlin.coroutines.intrinsics.a.a ? objA : Unit.a;
    }

    public final void c0() {
        E0 e0 = this.f;
        if (e0 == null) {
            return;
        }
        e0.n(kotlin.math.c.c(a0() * ((Number) e0.l.getValue()).longValue()));
    }

    public final void d0(float f) {
        this.i.j(f);
    }

    @Override // androidx.compose.animation.core.J0
    public final Object t() {
        return ((androidx.compose.runtime.L0) this.d).getValue();
    }
}

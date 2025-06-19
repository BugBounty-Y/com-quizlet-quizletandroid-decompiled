package androidx.compose.foundation.pager;

import androidx.camera.camera2.internal.p0;
import androidx.compose.foundation.gestures.C0350t;
import androidx.compose.foundation.gestures.E0;
import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.foundation.lazy.layout.AbstractC0448u;
import androidx.compose.foundation.lazy.layout.C0432d;
import androidx.compose.foundation.lazy.layout.X;
import androidx.compose.foundation.lazy.layout.Z;
import androidx.compose.foundation.lazy.layout.b0;
import androidx.compose.foundation.lazy.layout.c0;
import androidx.compose.foundation.u0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.F0;
import androidx.compose.runtime.H0;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import androidx.compose.runtime.V;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public abstract class E implements E0 {
    public final Z A;
    public final InterfaceC0773a0 B;
    public final InterfaceC0773a0 C;
    public final InterfaceC0773a0 D;
    public final InterfaceC0773a0 E;
    public final InterfaceC0773a0 F;
    public final InterfaceC0773a0 G;
    public final InterfaceC0773a0 a;
    public final com.google.android.gms.auth.api.signin.internal.h b;
    public final p0 c;
    public int d;
    public int e;
    public long f;
    public long g;
    public float h;
    public float i;
    public final C0350t j;
    public final boolean k;
    public int l;
    public b0 m;
    public boolean n;
    public final InterfaceC0773a0 o;
    public androidx.compose.ui.unit.b p;
    public final androidx.compose.foundation.interaction.m q;
    public final H0 r;
    public final H0 s;
    public final androidx.compose.runtime.E t;
    public final c0 u;
    public final com.airbnb.lottie.network.d v;
    public final C0432d w;
    public final InterfaceC0773a0 x;
    public final androidx.compose.foundation.lazy.v y;
    public long z;

    public E(float f, int i) {
        double d = f;
        if (-0.5d > d || d > 0.5d) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.i("currentPageOffsetFraction ", f, " is not within the range -0.5 to 0.5").toString());
        }
        this.a = C0776c.z(new androidx.compose.ui.geometry.b(0L));
        this.b = new com.google.android.gms.auth.api.signin.internal.h(this, 9);
        p0 p0Var = new p0();
        p0Var.c = this;
        p0Var.d = C0776c.w(i);
        p0Var.a = C0776c.v(f);
        p0Var.f = new X(i, 30, 100);
        this.c = p0Var;
        this.d = i;
        this.f = Long.MAX_VALUE;
        this.j = new C0350t(new androidx.camera.lifecycle.f(this, 18));
        this.k = true;
        this.l = -1;
        this.o = C0776c.y(I.b, V.c);
        this.p = I.c;
        this.q = new androidx.compose.foundation.interaction.m();
        this.r = C0776c.w(-1);
        this.s = C0776c.w(i);
        V v = V.f;
        C0776c.p(v, new D(this, 0));
        this.t = C0776c.p(v, new D(this, 1));
        this.u = new c0(null);
        this.v = new com.airbnb.lottie.network.d(9);
        this.w = new C0432d();
        this.x = C0776c.z(null);
        this.y = new androidx.compose.foundation.lazy.v(this, 2);
        this.z = L5.b(0, 0, 15);
        this.A = new Z();
        this.B = AbstractC0448u.g();
        this.C = AbstractC0448u.g();
        Boolean bool = Boolean.FALSE;
        this.D = C0776c.z(bool);
        this.E = C0776c.z(bool);
        this.F = C0776c.z(bool);
        this.G = C0776c.z(bool);
    }

    /* JADX WARN: Code restructure failed: missing block: B:26:0x0077, code lost:
    
        if (r5.j.c(r6, r7, r0) == r1) goto L27;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.Object r(androidx.compose.foundation.pager.E r5, androidx.compose.foundation.u0 r6, kotlin.jvm.functions.Function2 r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            boolean r0 = r8 instanceof androidx.compose.foundation.pager.B
            if (r0 == 0) goto L13
            r0 = r8
            androidx.compose.foundation.pager.B r0 = (androidx.compose.foundation.pager.B) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            androidx.compose.foundation.pager.B r0 = new androidx.compose.foundation.pager.B
            r0.<init>(r5, r8)
        L18:
            java.lang.Object r8 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3e
            if (r2 == r4) goto L34
            if (r2 != r3) goto L2c
            androidx.compose.foundation.pager.E r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L7a
        L2c:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L34:
            kotlin.jvm.functions.Function2 r7 = r0.l
            androidx.compose.foundation.u0 r6 = r0.k
            androidx.compose.foundation.pager.E r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L57
        L3e:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r0.j = r5
            r0.k = r6
            r0.l = r7
            r0.o = r4
            androidx.compose.foundation.lazy.layout.d r8 = r5.w
            java.lang.Object r8 = r8.l(r0)
            if (r8 != r1) goto L52
            goto L54
        L52:
            kotlin.Unit r8 = kotlin.Unit.a
        L54:
            if (r8 != r1) goto L57
            goto L79
        L57:
            androidx.compose.foundation.gestures.t r8 = r5.j
            boolean r8 = r8.a()
            if (r8 != 0) goto L68
            int r8 = r5.j()
            androidx.compose.runtime.H0 r2 = r5.s
            r2.j(r8)
        L68:
            r0.j = r5
            r8 = 0
            r0.k = r8
            r0.l = r8
            r0.o = r3
            androidx.compose.foundation.gestures.t r8 = r5.j
            java.lang.Object r6 = r8.c(r6, r7, r0)
            if (r6 != r1) goto L7a
        L79:
            return r1
        L7a:
            androidx.compose.runtime.H0 r5 = r5.r
            r6 = -1
            r5.j(r6)
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.pager.E.r(androidx.compose.foundation.pager.E, androidx.compose.foundation.u0, kotlin.jvm.functions.Function2, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static Object s(C0466e c0466e, int i, kotlin.coroutines.jvm.internal.i iVar) {
        c0466e.getClass();
        Object objC = c0466e.c(u0.a, new C(c0466e, i, null), iVar);
        return objC == kotlin.coroutines.intrinsics.a.a ? objC : Unit.a;
    }

    @Override // androidx.compose.foundation.gestures.E0
    public final boolean a() {
        return this.j.a();
    }

    @Override // androidx.compose.foundation.gestures.E0
    public final boolean b() {
        return ((Boolean) ((L0) this.E).getValue()).booleanValue();
    }

    @Override // androidx.compose.foundation.gestures.E0
    public final Object c(u0 u0Var, Function2 function2, kotlin.coroutines.jvm.internal.c cVar) {
        return r(this, u0Var, function2, cVar);
    }

    @Override // androidx.compose.foundation.gestures.E0
    public final boolean d() {
        return ((Boolean) ((L0) this.D).getValue()).booleanValue();
    }

    @Override // androidx.compose.foundation.gestures.E0
    public final float e(float f) {
        return this.j.e(f);
    }

    /* JADX WARN: Code restructure failed: missing block: B:44:0x00bb, code lost:
    
        if (r13 == r1) goto L45;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r14v9, types: [androidx.compose.animation.core.n] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object f(int r13, androidx.compose.animation.core.C0253l0 r14, kotlin.coroutines.jvm.internal.c r15) {
        /*
            Method dump skipped, instructions count: 211
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.pager.E.f(int, androidx.compose.animation.core.l0, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Type inference failed for: r5v0, types: [java.lang.Object, java.util.Collection, java.util.List] */
    public final void h(x xVar, boolean z) {
        p0 p0Var = this.c;
        boolean z2 = true;
        if (z) {
            ((F0) p0Var.a).j(xVar.k);
        } else {
            p0Var.getClass();
            C0472k c0472k = xVar.j;
            p0Var.e = c0472k != null ? c0472k.d : null;
            boolean z3 = p0Var.b;
            ?? r5 = xVar.a;
            if (z3 || !r5.isEmpty()) {
                p0Var.b = true;
                int i = c0472k != null ? c0472k.a : 0;
                float f = xVar.k;
                ((H0) p0Var.d).j(i);
                ((X) p0Var.f).a(i);
                ((F0) p0Var.a).j(f);
            }
            if (this.l != -1 && !r5.isEmpty()) {
                boolean z4 = this.n;
                int i2 = xVar.h;
                if (this.l != (z4 ? ((C0472k) CollectionsKt.U(r5)).a + i2 + 1 : (((C0472k) CollectionsKt.L(r5)).a - i2) - 1)) {
                    this.l = -1;
                    b0 b0Var = this.m;
                    if (b0Var != null) {
                        b0Var.cancel();
                    }
                    this.m = null;
                }
            }
        }
        ((L0) this.o).setValue(xVar);
        ((L0) this.D).setValue(Boolean.valueOf(xVar.m));
        C0472k c0472k2 = xVar.i;
        if ((c0472k2 != null ? c0472k2.a : 0) == 0 && xVar.l == 0) {
            z2 = false;
        }
        ((L0) this.E).setValue(Boolean.valueOf(z2));
        if (c0472k2 != null) {
            this.d = c0472k2.a;
        }
        this.e = xVar.l;
        androidx.compose.runtime.snapshots.h hVarD = androidx.compose.runtime.snapshots.r.d();
        Function1 function1E = hVarD != null ? hVarD.e() : null;
        androidx.compose.runtime.snapshots.h hVarE = androidx.compose.runtime.snapshots.r.e(hVarD);
        try {
            if (Math.abs(this.i) > 0.5f && this.k && p(this.i)) {
                q(this.i, xVar);
            }
            Unit unit = Unit.a;
            androidx.compose.runtime.snapshots.r.g(hVarD, hVarE, function1E);
            this.f = I.a(xVar, l());
            l();
            EnumC0320d0 enumC0320d0 = EnumC0320d0.b;
            EnumC0320d0 enumC0320d02 = xVar.e;
            long jA = xVar.a();
            int i3 = (int) (enumC0320d02 == enumC0320d0 ? jA >> 32 : jA & 4294967295L);
            xVar.n.getClass();
            this.g = kotlin.ranges.l.c(0, 0, i3);
        } catch (Throwable th) {
            androidx.compose.runtime.snapshots.r.g(hVarD, hVarE, function1E);
            throw th;
        }
    }

    public final int i(int i) {
        if (l() > 0) {
            return kotlin.ranges.l.c(i, 0, l() - 1);
        }
        return 0;
    }

    public final int j() {
        return ((H0) this.c.d).i();
    }

    public final x k() {
        return (x) ((L0) this.o).getValue();
    }

    public abstract int l();

    public final int m() {
        return ((x) ((L0) this.o).getValue()).b;
    }

    public final int n() {
        return ((x) ((L0) this.o).getValue()).c + m();
    }

    public final long o() {
        return ((androidx.compose.ui.geometry.b) ((L0) this.a).getValue()).a;
    }

    public final boolean p(float f) {
        if (k().e == EnumC0320d0.a) {
            if (Math.signum(f) == Math.signum(-androidx.compose.ui.geometry.b.e(o()))) {
                return true;
            }
        } else if (Math.signum(f) == Math.signum(-androidx.compose.ui.geometry.b.d(o()))) {
            return true;
        }
        return ((int) androidx.compose.ui.geometry.b.d(o())) == 0 && ((int) androidx.compose.ui.geometry.b.e(o())) == 0;
    }

    /* JADX WARN: Type inference failed for: r0v1, types: [java.lang.Object, java.util.Collection, java.util.List] */
    public final void q(float f, x xVar) {
        b0 b0Var;
        b0 b0Var2;
        b0 b0Var3;
        if (this.k) {
            ?? r0 = xVar.a;
            if (r0.isEmpty()) {
                return;
            }
            boolean z = f > DefinitionKt.NO_Float_VALUE;
            int i = xVar.h;
            int i2 = z ? ((C0472k) CollectionsKt.U(r0)).a + i + 1 : (((C0472k) CollectionsKt.L(r0)).a - i) - 1;
            if (i2 < 0 || i2 >= l()) {
                return;
            }
            if (i2 != this.l) {
                if (this.n != z && (b0Var3 = this.m) != null) {
                    b0Var3.cancel();
                }
                this.n = z;
                this.l = i2;
                this.m = this.u.a(i2, this.z);
            }
            if (z) {
                if ((((C0472k) CollectionsKt.U(r0)).l + (xVar.b + xVar.c)) - xVar.g >= f || (b0Var2 = this.m) == null) {
                    return;
                }
                b0Var2.a();
                return;
            }
            if (xVar.f - ((C0472k) CollectionsKt.L(r0)).l >= (-f) || (b0Var = this.m) == null) {
                return;
            }
            b0Var.a();
        }
    }
}

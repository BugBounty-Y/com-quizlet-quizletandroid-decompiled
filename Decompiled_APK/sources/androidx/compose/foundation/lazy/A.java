package androidx.compose.foundation.lazy;

import androidx.appcompat.app.Q;
import androidx.appcompat.widget.C0070a;
import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.animation.core.C0258o;
import androidx.compose.animation.core.C0260p;
import androidx.compose.animation.core.M0;
import androidx.compose.animation.d0;
import androidx.compose.foundation.gestures.C0350t;
import androidx.compose.foundation.gestures.E0;
import androidx.compose.foundation.lazy.layout.AbstractC0439k;
import androidx.compose.foundation.lazy.layout.AbstractC0448u;
import androidx.compose.foundation.lazy.layout.C0432d;
import androidx.compose.foundation.lazy.layout.C0438j;
import androidx.compose.foundation.lazy.layout.K;
import androidx.compose.foundation.lazy.layout.Z;
import androidx.compose.foundation.lazy.layout.b0;
import androidx.compose.foundation.lazy.layout.c0;
import androidx.compose.foundation.u0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import androidx.compose.runtime.V;
import com.google.android.gms.internal.mlkit_vision_barcode.K4;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class A implements E0 {
    public static final com.quizlet.data.repository.explanations.myexplanations.a x = K4.b(t.a, o.d);
    public final C0070a a;
    public boolean b;
    public q c;
    public final s d;
    public final Q e;
    public final InterfaceC0773a0 f;
    public final androidx.compose.foundation.interaction.m g;
    public float h;
    public final C0350t i;
    public final boolean j;
    public androidx.compose.ui.node.E k;
    public final v l;
    public final C0432d m;
    public final K n;
    public final com.airbnb.lottie.network.d o;
    public final c0 p;
    public final androidx.webkit.internal.p q;
    public final Z r;
    public final InterfaceC0773a0 s;
    public final InterfaceC0773a0 t;
    public final InterfaceC0773a0 u;
    public final InterfaceC0773a0 v;
    public C0258o w;

    public A(int i, int i2) {
        C0070a c0070a = new C0070a();
        c0070a.a = -1;
        this.a = c0070a;
        this.d = new s(i, i2, 0);
        this.e = new Q(this);
        this.f = C0776c.y(D.b, V.c);
        this.g = new androidx.compose.foundation.interaction.m();
        this.i = new C0350t(new androidx.camera.lifecycle.f(this, 14));
        this.j = true;
        this.l = new v(this, 0);
        this.m = new C0432d();
        this.n = new K();
        this.o = new com.airbnb.lottie.network.d(9);
        this.p = new c0(new u(this, i, 0));
        this.q = new androidx.webkit.internal.p(this, 4);
        this.r = new Z();
        this.s = AbstractC0448u.g();
        Boolean bool = Boolean.FALSE;
        this.t = C0776c.z(bool);
        this.u = C0776c.z(bool);
        this.v = AbstractC0448u.g();
        this.w = new C0258o(M0.a, Float.valueOf(DefinitionKt.NO_Float_VALUE), new C0260p(DefinitionKt.NO_Float_VALUE), Long.MIN_VALUE, Long.MIN_VALUE, false);
    }

    public static Object j(A a, int i, kotlin.coroutines.jvm.internal.i iVar) {
        a.getClass();
        Object objC = a.c(u0.a, new x(a, i, null), iVar);
        return objC == kotlin.coroutines.intrinsics.a.a ? objC : Unit.a;
    }

    @Override // androidx.compose.foundation.gestures.E0
    public final boolean a() {
        return this.i.a();
    }

    @Override // androidx.compose.foundation.gestures.E0
    public final boolean b() {
        return ((Boolean) ((L0) this.u).getValue()).booleanValue();
    }

    /* JADX WARN: Code restructure failed: missing block: B:21:0x0060, code lost:
    
        if (r8.c(r6, r7, r0) == r1) goto L22;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // androidx.compose.foundation.gestures.E0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object c(androidx.compose.foundation.u0 r6, kotlin.jvm.functions.Function2 r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r5 = this;
            boolean r0 = r8 instanceof androidx.compose.foundation.lazy.w
            if (r0 == 0) goto L13
            r0 = r8
            androidx.compose.foundation.lazy.w r0 = (androidx.compose.foundation.lazy.w) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            androidx.compose.foundation.lazy.w r0 = new androidx.compose.foundation.lazy.w
            r0.<init>(r5, r8)
        L18:
            java.lang.Object r8 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3c
            if (r2 == r4) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L63
        L2a:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L32:
            kotlin.jvm.functions.Function2 r7 = r0.l
            androidx.compose.foundation.u0 r6 = r0.k
            androidx.compose.foundation.lazy.A r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L51
        L3c:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r0.j = r5
            r0.k = r6
            r0.l = r7
            r0.o = r4
            androidx.compose.foundation.lazy.layout.d r8 = r5.m
            java.lang.Object r8 = r8.l(r0)
            if (r8 != r1) goto L50
            goto L62
        L50:
            r2 = r5
        L51:
            androidx.compose.foundation.gestures.t r8 = r2.i
            r2 = 0
            r0.j = r2
            r0.k = r2
            r0.l = r2
            r0.o = r3
            java.lang.Object r6 = r8.c(r6, r7, r0)
            if (r6 != r1) goto L63
        L62:
            return r1
        L63:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.lazy.A.c(androidx.compose.foundation.u0, kotlin.jvm.functions.Function2, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // androidx.compose.foundation.gestures.E0
    public final boolean d() {
        return ((Boolean) ((L0) this.t).getValue()).booleanValue();
    }

    @Override // androidx.compose.foundation.gestures.E0
    public final float e(float f) {
        return this.i.e(f);
    }

    public final Object f(int i, int i2, kotlin.coroutines.jvm.internal.i iVar) {
        androidx.compose.ui.unit.b bVar = ((q) ((L0) this.f).getValue()).h;
        float f = AbstractC0439k.a;
        Q q = this.e;
        Object objC = ((A) q.a).c(u0.a, new C0438j(i, bVar, q, i2, null), iVar);
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        if (objC != aVar) {
            objC = Unit.a;
        }
        if (objC != aVar) {
            objC = Unit.a;
        }
        return objC == aVar ? objC : Unit.a;
    }

    /* JADX WARN: Type inference failed for: r1v2, types: [java.lang.Object, java.util.Collection, java.util.List] */
    public final void g(q qVar, boolean z, boolean z2) {
        if (!z && this.b) {
            this.c = qVar;
            return;
        }
        if (z) {
            this.b = true;
        }
        r rVar = qVar.a;
        ((L0) this.u).setValue(Boolean.valueOf(((rVar != null ? rVar.a : 0) == 0 && qVar.b == 0) ? false : true));
        ((L0) this.t).setValue(Boolean.valueOf(qVar.c));
        this.h -= qVar.d;
        ((L0) this.f).setValue(qVar);
        s sVar = this.d;
        if (z2) {
            int i = qVar.b;
            if (i < DefinitionKt.NO_Float_VALUE) {
                sVar.getClass();
                throw new IllegalStateException(("scrollOffset should be non-negative (" + i + ')').toString());
            }
            sVar.c.j(i);
        } else {
            sVar.getClass();
            sVar.e = rVar != null ? rVar.k : null;
            if (sVar.d || qVar.m > 0) {
                sVar.d = true;
                int i2 = qVar.b;
                if (i2 < DefinitionKt.NO_Float_VALUE) {
                    throw new IllegalStateException(d0.m(')', i2, "scrollOffset should be non-negative (").toString());
                }
                sVar.c(rVar != null ? rVar.a : 0, i2);
            }
            if (this.j) {
                C0070a c0070a = this.a;
                if (c0070a.a != -1) {
                    ?? r1 = qVar.j;
                    if (!r1.isEmpty()) {
                        if (c0070a.a != (c0070a.b ? ((r) CollectionsKt.U(r1)).a + 1 : ((r) CollectionsKt.L(r1)).a - 1)) {
                            c0070a.a = -1;
                            b0 b0Var = (b0) c0070a.c;
                            if (b0Var != null) {
                                b0Var.cancel();
                            }
                            c0070a.c = null;
                        }
                    }
                }
            }
        }
        if (z) {
            float fC0 = qVar.h.c0(D.a);
            float f = qVar.e;
            if (f <= fC0) {
                return;
            }
            androidx.compose.runtime.snapshots.h hVarD = androidx.compose.runtime.snapshots.r.d();
            Function1 function1E = hVarD != null ? hVarD.e() : null;
            androidx.compose.runtime.snapshots.h hVarE = androidx.compose.runtime.snapshots.r.e(hVarD);
            try {
                float fFloatValue = ((Number) ((L0) this.w.b).getValue()).floatValue();
                C0258o c0258o = this.w;
                boolean z3 = c0258o.f;
                kotlinx.coroutines.C c = qVar.g;
                if (z3) {
                    this.w = AbstractC0240f.l(c0258o, fFloatValue - f, DefinitionKt.NO_Float_VALUE, 30);
                    kotlinx.coroutines.E.A(c, null, null, new y(this, null), 3);
                } else {
                    this.w = new C0258o(M0.a, Float.valueOf(-f), null, 60);
                    kotlinx.coroutines.E.A(c, null, null, new z(this, null), 3);
                }
                androidx.compose.runtime.snapshots.r.g(hVarD, hVarE, function1E);
            } catch (Throwable th) {
                androidx.compose.runtime.snapshots.r.g(hVarD, hVarE, function1E);
                throw th;
            }
        }
    }

    public final q h() {
        return (q) ((L0) this.f).getValue();
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [java.lang.Object, java.util.Collection] */
    /* JADX WARN: Type inference failed for: r3v0, types: [java.lang.Object, java.util.List] */
    public final void i(float f, q qVar) {
        b0 b0Var;
        b0 b0Var2;
        b0 b0Var3;
        if (this.j) {
            C0070a c0070a = this.a;
            if (qVar.j.isEmpty()) {
                return;
            }
            boolean z = f < DefinitionKt.NO_Float_VALUE;
            ?? r3 = qVar.j;
            int i = z ? ((r) CollectionsKt.U(r3)).a + 1 : ((r) CollectionsKt.L(r3)).a - 1;
            if (i < 0 || i >= qVar.m) {
                return;
            }
            if (i != c0070a.a) {
                if (c0070a.b != z && (b0Var3 = (b0) c0070a.c) != null) {
                    b0Var3.cancel();
                }
                c0070a.b = z;
                c0070a.a = i;
                A a = (A) this.q.b;
                androidx.compose.runtime.snapshots.h hVarD = androidx.compose.runtime.snapshots.r.d();
                Function1 function1E = hVarD != null ? hVarD.e() : null;
                androidx.compose.runtime.snapshots.h hVarE = androidx.compose.runtime.snapshots.r.e(hVarD);
                try {
                    long j = ((q) ((L0) a.f).getValue()).i;
                    androidx.compose.runtime.snapshots.r.g(hVarD, hVarE, function1E);
                    c0070a.c = a.p.a(i, j);
                } catch (Throwable th) {
                    androidx.compose.runtime.snapshots.r.g(hVarD, hVarE, function1E);
                    throw th;
                }
            }
            if (!z) {
                if (qVar.k - ((r) CollectionsKt.L(r3)).o >= f || (b0Var = (b0) c0070a.c) == null) {
                    return;
                }
                b0Var.a();
                return;
            }
            r rVar = (r) CollectionsKt.U(r3);
            if (((rVar.o + rVar.p) + qVar.p) - qVar.l >= (-f) || (b0Var2 = (b0) c0070a.c) == null) {
                return;
            }
            b0Var2.a();
        }
    }

    public final void k(int i, int i2) {
        s sVar = this.d;
        if (sVar.a() != i || sVar.b() != i2) {
            this.n.f();
        }
        sVar.c(i, i2);
        sVar.e = null;
        androidx.compose.ui.node.E e = this.k;
        if (e != null) {
            e.k();
        }
    }
}

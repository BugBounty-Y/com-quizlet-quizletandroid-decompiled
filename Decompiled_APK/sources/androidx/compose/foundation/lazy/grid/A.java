package androidx.compose.foundation.lazy.grid;

import androidx.appcompat.widget.C0070a;
import androidx.compose.animation.d0;
import androidx.compose.foundation.gestures.C0350t;
import androidx.compose.foundation.gestures.E0;
import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.foundation.lazy.layout.AbstractC0448u;
import androidx.compose.foundation.lazy.layout.C0432d;
import androidx.compose.foundation.lazy.layout.K;
import androidx.compose.foundation.lazy.layout.Z;
import androidx.compose.foundation.lazy.layout.b0;
import androidx.compose.foundation.lazy.layout.c0;
import androidx.compose.foundation.u0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import androidx.compose.runtime.V;
import androidx.compose.ui.node.E;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3101b0;
import com.google.android.gms.internal.mlkit_vision_barcode.K4;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.List;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class A implements E0 {
    public static final com.quizlet.data.repository.explanations.myexplanations.a t = K4.b(g.c, o.d);
    public final C0070a a;
    public final androidx.compose.foundation.lazy.s b;
    public final InterfaceC0773a0 c;
    public final androidx.compose.foundation.interaction.m d;
    public float e;
    public final C0350t f;
    public final boolean g;
    public E h;
    public final androidx.compose.foundation.lazy.v i;
    public final C0432d j;
    public final K k;
    public final com.airbnb.lottie.network.d l;
    public final c0 m;
    public final com.airbnb.lottie.network.c n;
    public final Z o;
    public final InterfaceC0773a0 p;
    public final InterfaceC0773a0 q;
    public final InterfaceC0773a0 r;
    public final InterfaceC0773a0 s;

    public A(int i, int i2) {
        C0070a c0070a = new C0070a();
        c0070a.a = -1;
        c0070a.c = new androidx.compose.runtime.collection.b(new b0[16]);
        this.a = c0070a;
        this.b = new androidx.compose.foundation.lazy.s(i, i2, 1);
        this.c = C0776c.y(B.a, V.c);
        this.d = new androidx.compose.foundation.interaction.m();
        this.f = new C0350t(new androidx.camera.lifecycle.f(this, 15));
        this.g = true;
        this.i = new androidx.compose.foundation.lazy.v(this, 1);
        this.j = new C0432d();
        this.k = new K();
        this.l = new com.airbnb.lottie.network.d(9);
        this.m = new c0(new androidx.compose.foundation.lazy.u(this, i, 1));
        this.n = new com.airbnb.lottie.network.c(this, 7);
        this.o = new Z();
        this.p = AbstractC0448u.g();
        this.q = AbstractC0448u.g();
        Boolean bool = Boolean.FALSE;
        this.r = C0776c.z(bool);
        this.s = C0776c.z(bool);
    }

    public static Object i(A a, int i, kotlin.coroutines.jvm.internal.i iVar) {
        a.getClass();
        Object objC = a.c(u0.a, new z(a, i, null), iVar);
        return objC == kotlin.coroutines.intrinsics.a.a ? objC : Unit.a;
    }

    @Override // androidx.compose.foundation.gestures.E0
    public final boolean a() {
        return this.f.a();
    }

    @Override // androidx.compose.foundation.gestures.E0
    public final boolean b() {
        return ((Boolean) ((L0) this.s).getValue()).booleanValue();
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
            boolean r0 = r8 instanceof androidx.compose.foundation.lazy.grid.y
            if (r0 == 0) goto L13
            r0 = r8
            androidx.compose.foundation.lazy.grid.y r0 = (androidx.compose.foundation.lazy.grid.y) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            androidx.compose.foundation.lazy.grid.y r0 = new androidx.compose.foundation.lazy.grid.y
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
            androidx.compose.foundation.lazy.grid.A r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L51
        L3c:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r0.j = r5
            r0.k = r6
            r0.l = r7
            r0.o = r4
            androidx.compose.foundation.lazy.layout.d r8 = r5.j
            java.lang.Object r8 = r8.l(r0)
            if (r8 != r1) goto L50
            goto L62
        L50:
            r2 = r5
        L51:
            androidx.compose.foundation.gestures.t r8 = r2.f
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
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.lazy.grid.A.c(androidx.compose.foundation.u0, kotlin.jvm.functions.Function2, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // androidx.compose.foundation.gestures.E0
    public final boolean d() {
        return ((Boolean) ((L0) this.r).getValue()).booleanValue();
    }

    @Override // androidx.compose.foundation.gestures.E0
    public final float e(float f) {
        return this.f.e(f);
    }

    /* JADX WARN: Type inference failed for: r1v9, types: [java.lang.Object, java.util.Collection, java.util.List] */
    public final void f(q qVar, boolean z) {
        r rVar;
        int i;
        r rVar2;
        this.e -= qVar.d;
        ((L0) this.c).setValue(qVar);
        int i2 = 0;
        s sVar = qVar.a;
        ((L0) this.s).setValue(Boolean.valueOf(((sVar != null ? sVar.a : 0) == 0 && qVar.b == 0) ? false : true));
        ((L0) this.r).setValue(Boolean.valueOf(qVar.c));
        androidx.compose.foundation.lazy.s sVar2 = this.b;
        if (z) {
            int i3 = qVar.b;
            if (i3 >= DefinitionKt.NO_Float_VALUE) {
                sVar2.c.j(i3);
                return;
            }
            sVar2.getClass();
            throw new IllegalStateException(("scrollOffset should be non-negative (" + i3 + ')').toString());
        }
        sVar2.getClass();
        sVar2.e = (sVar == null || (rVar2 = (r) C4933y.B(sVar.b)) == null) ? null : rVar2.b;
        if (sVar2.d || qVar.j > 0) {
            sVar2.d = true;
            int i4 = qVar.b;
            if (i4 < DefinitionKt.NO_Float_VALUE) {
                throw new IllegalStateException(d0.m(')', i4, "scrollOffset should be non-negative (").toString());
            }
            sVar2.c((sVar == null || (rVar = (r) C4933y.B(sVar.b)) == null) ? 0 : rVar.a, i4);
        }
        if (this.g) {
            C0070a c0070a = this.a;
            if (c0070a.a != -1) {
                ?? r1 = qVar.g;
                if (r1.isEmpty()) {
                    return;
                }
                boolean z2 = c0070a.b;
                EnumC0320d0 enumC0320d0 = EnumC0320d0.a;
                EnumC0320d0 enumC0320d02 = qVar.k;
                if (z2) {
                    r rVar3 = (r) CollectionsKt.U(r1);
                    i = (enumC0320d02 == enumC0320d0 ? rVar3.u : rVar3.v) + 1;
                } else {
                    r rVar4 = (r) CollectionsKt.L(r1);
                    i = (enumC0320d02 == enumC0320d0 ? rVar4.u : rVar4.v) - 1;
                }
                if (c0070a.a != i) {
                    c0070a.a = -1;
                    androidx.compose.runtime.collection.b bVar = (androidx.compose.runtime.collection.b) c0070a.c;
                    int i5 = bVar.c;
                    if (i5 > 0) {
                        Object[] objArr = bVar.a;
                        do {
                            ((b0) objArr[i2]).cancel();
                            i2++;
                        } while (i2 < i5);
                    }
                    bVar.i();
                }
            }
        }
    }

    public final q g() {
        return (q) ((L0) this.c).getValue();
    }

    /* JADX WARN: Type inference failed for: r3v12, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r5v0, types: [java.lang.Object, java.util.Collection] */
    /* JADX WARN: Type inference failed for: r9v0, types: [java.lang.Object, java.util.List] */
    public final void h(float f, q qVar) {
        int i;
        int i2;
        boolean z;
        int i3;
        int i4;
        int i5;
        if (this.g) {
            C0070a c0070a = this.a;
            c0070a.getClass();
            if (qVar.g.isEmpty()) {
                return;
            }
            boolean z2 = f < DefinitionKt.NO_Float_VALUE;
            EnumC0320d0 enumC0320d0 = EnumC0320d0.a;
            EnumC0320d0 enumC0320d02 = qVar.k;
            ?? r9 = qVar.g;
            if (z2) {
                r rVar = (r) CollectionsKt.U(r9);
                i = (enumC0320d02 == enumC0320d0 ? rVar.u : rVar.v) + 1;
                i2 = ((r) CollectionsKt.U(r9)).a + 1;
            } else {
                r rVar2 = (r) CollectionsKt.L(r9);
                i = (enumC0320d02 == enumC0320d0 ? rVar2.u : rVar2.v) - 1;
                i2 = ((r) CollectionsKt.L(r9)).a - 1;
            }
            if (i2 < 0 || i2 >= qVar.j) {
                return;
            }
            int i6 = c0070a.a;
            androidx.compose.runtime.collection.b bVar = (androidx.compose.runtime.collection.b) c0070a.c;
            if (i == i6 || i < 0) {
                z = z2;
            } else {
                if (c0070a.b != z2 && (i5 = bVar.c) > 0) {
                    Object[] objArr = bVar.a;
                    int i7 = 0;
                    do {
                        ((b0) objArr[i7]).cancel();
                        i7++;
                    } while (i7 < i5);
                }
                c0070a.b = z2;
                c0070a.a = i;
                bVar.i();
                com.airbnb.lottie.network.c cVar = this.n;
                cVar.getClass();
                ArrayList arrayList = new ArrayList();
                A a = (A) cVar.b;
                androidx.compose.runtime.snapshots.h hVarD = androidx.compose.runtime.snapshots.r.d();
                Function1 function1E = hVarD != null ? hVarD.e() : null;
                androidx.compose.runtime.snapshots.h hVarE = androidx.compose.runtime.snapshots.r.e(hVarD);
                try {
                    List list = (List) ((q) ((L0) a.c).getValue()).f.invoke(Integer.valueOf(i));
                    int size = list.size();
                    int i8 = 0;
                    while (i8 < size) {
                        Pair pair = (Pair) list.get(i8);
                        arrayList.add(a.m.a(((Number) pair.a).intValue(), ((androidx.compose.ui.unit.a) pair.b).a));
                        i8++;
                        list = list;
                        a = a;
                        z2 = z2;
                    }
                    z = z2;
                    Unit unit = Unit.a;
                    androidx.compose.runtime.snapshots.r.g(hVarD, hVarE, function1E);
                    bVar.e(bVar.c, arrayList);
                } catch (Throwable th) {
                    androidx.compose.runtime.snapshots.r.g(hVarD, hVarE, function1E);
                    throw th;
                }
            }
            if (!z) {
                if (qVar.h - AbstractC3101b0.b((r) CollectionsKt.L(r9), enumC0320d02) >= f || (i3 = bVar.c) <= 0) {
                    return;
                }
                Object[] objArr2 = bVar.a;
                int i9 = 0;
                do {
                    ((b0) objArr2[i9]).a();
                    i9++;
                } while (i9 < i3);
                return;
            }
            r rVar3 = (r) CollectionsKt.U(r9);
            if (((AbstractC3101b0.b(rVar3, enumC0320d02) + ((int) (enumC0320d02 == enumC0320d0 ? rVar3.s & 4294967295L : rVar3.s >> 32))) + qVar.m) - qVar.i >= (-f) || (i4 = bVar.c) <= 0) {
                return;
            }
            Object[] objArr3 = bVar.a;
            int i10 = 0;
            do {
                ((b0) objArr3[i10]).a();
                i10++;
            } while (i10 < i4);
        }
    }
}

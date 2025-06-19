package androidx.compose.runtime;

import android.os.Trace;
import androidx.collection.C0223v;
import androidx.compose.runtime.changelist.C0778a;
import com.google.android.gms.internal.mlkit_vision_barcode.F4;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.KotlinNothingValueException;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.runtime.w, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0833w implements InterfaceC0815p0, InterfaceC0819s {
    public final AbstractC0827t a;
    public final AbstractC0772a b;
    public final AtomicReference c = new AtomicReference(null);
    public final Object d = new Object();
    public final androidx.collection.M e;
    public final A0 f;
    public final androidx.collection.I g;
    public final androidx.collection.J h;
    public final androidx.collection.J i;
    public final androidx.collection.I j;
    public final C0778a k;
    public final C0778a l;
    public final androidx.collection.I m;
    public androidx.collection.I n;
    public boolean o;
    public C0833w p;
    public int q;
    public final V r;
    public final C0814p s;
    public boolean t;

    public C0833w(AbstractC0827t abstractC0827t, AbstractC0772a abstractC0772a) {
        this.a = abstractC0827t;
        this.b = abstractC0772a;
        androidx.collection.M m = new androidx.collection.M(new androidx.collection.J());
        this.e = m;
        A0 a0 = new A0();
        if (abstractC0827t.d()) {
            a0.k = new C0223v();
        }
        if (abstractC0827t.f()) {
            a0.b();
        }
        this.f = a0;
        this.g = F4.c();
        this.h = new androidx.collection.J();
        this.i = new androidx.collection.J();
        this.j = F4.c();
        C0778a c0778a = new C0778a();
        this.k = c0778a;
        C0778a c0778a2 = new C0778a();
        this.l = c0778a2;
        this.m = F4.c();
        this.n = F4.c();
        this.r = new V(7);
        C0814p c0814p = new C0814p(abstractC0772a, abstractC0827t, a0, m, c0778a, c0778a2, this);
        abstractC0827t.o(c0814p);
        this.s = c0814p;
        boolean z = abstractC0827t instanceof C0832v0;
        androidx.compose.runtime.internal.d dVar = AbstractC0800i.a;
    }

    @Override // androidx.compose.runtime.InterfaceC0815p0
    public final void a() {
        this.o = true;
    }

    @Override // androidx.compose.runtime.InterfaceC0815p0
    public final P b(C0813o0 c0813o0, Object obj) {
        C0833w c0833w;
        int i = c0813o0.a;
        if ((i & 2) != 0) {
            c0813o0.a = i | 4;
        }
        C0774b c0774b = c0813o0.c;
        if (c0774b == null || !c0774b.a()) {
            return P.a;
        }
        if (this.f.h(c0774b)) {
            return c0813o0.d != null ? t(c0813o0, c0774b, obj) : P.a;
        }
        synchronized (this.d) {
            c0833w = this.p;
        }
        if (c0833w != null) {
            C0814p c0814p = c0833w.s;
            if (c0814p.E && c0814p.d0(c0813o0, obj)) {
                return P.d;
            }
        }
        return P.a;
    }

    @Override // androidx.compose.runtime.InterfaceC0815p0
    public final void c(Object obj) {
        C0813o0 c0813o0V;
        boolean z;
        boolean z2;
        int i;
        int i2;
        C0814p c0814p = this.s;
        if (c0814p.z <= 0 && (c0813o0V = c0814p.v()) != null) {
            boolean z3 = true;
            int i3 = c0813o0V.a | 1;
            c0813o0V.a = i3;
            if ((i3 & 32) == 0) {
                androidx.collection.C c = c0813o0V.f;
                if (c == null) {
                    c = new androidx.collection.C();
                    c0813o0V.f = c;
                }
                int i4 = c0813o0V.e;
                int iB = c.b(obj);
                if (iB < 0) {
                    iB = ~iB;
                    i2 = -1;
                } else {
                    i2 = c.c[iB];
                }
                c.b[iB] = obj;
                c.c[iB] = i4;
                if (i2 == c0813o0V.e) {
                    return;
                }
            }
            if (obj instanceof androidx.compose.runtime.snapshots.A) {
                ((androidx.compose.runtime.snapshots.A) obj).h(1);
            }
            F4.b(this.g, obj, c0813o0V);
            if (obj instanceof E) {
                E e = (E) obj;
                D dJ = e.j();
                androidx.collection.I i5 = this.j;
                F4.e(i5, obj);
                androidx.collection.C c2 = dJ.e;
                Object[] objArr = c2.b;
                long[] jArr = c2.a;
                int length = jArr.length - 2;
                if (length >= 0) {
                    int i6 = 0;
                    while (true) {
                        long j = jArr[i6];
                        if ((((~j) << 7) & j & (-9187201950435737472L)) != -9187201950435737472L) {
                            int i7 = 8;
                            int i8 = 8 - ((~(i6 - length)) >>> 31);
                            int i9 = 0;
                            while (i9 < i8) {
                                if ((j & 255) < 128) {
                                    i = i7;
                                    androidx.compose.runtime.snapshots.z zVar = (androidx.compose.runtime.snapshots.z) objArr[(i6 << 3) + i9];
                                    if (zVar instanceof androidx.compose.runtime.snapshots.A) {
                                        z2 = true;
                                        ((androidx.compose.runtime.snapshots.A) zVar).h(1);
                                    } else {
                                        z2 = true;
                                    }
                                    F4.b(i5, zVar, obj);
                                } else {
                                    z2 = z3;
                                    i = i7;
                                }
                                j >>= i;
                                i9++;
                                z3 = z2;
                                i7 = i;
                            }
                            z = z3;
                            if (i8 != i7) {
                                break;
                            }
                        } else {
                            z = z3;
                        }
                        if (i6 == length) {
                            break;
                        }
                        i6++;
                        z3 = z;
                    }
                }
                Object obj2 = dJ.f;
                androidx.collection.I i10 = c0813o0V.g;
                if (i10 == null) {
                    i10 = new androidx.collection.I();
                    c0813o0V.g = i10;
                }
                i10.j(e, obj2);
            }
        }
    }

    public final void d() {
        this.c.set(null);
        this.k.b.b();
        this.l.b.b();
        androidx.collection.M m = this.e;
        if (m.a.g()) {
            return;
        }
        new ArrayList();
        if (m.a.g()) {
            return;
        }
        Trace.beginSection("Compose:abandons");
        try {
            androidx.collection.L l = new androidx.collection.L(m);
            kotlin.sequences.h hVar = (kotlin.sequences.h) l.c;
            while (hVar.hasNext()) {
                InterfaceC0834w0 interfaceC0834w0 = (InterfaceC0834w0) hVar.next();
                l.remove();
                interfaceC0834w0.a();
            }
            Unit unit = Unit.a;
            Trace.endSection();
        } catch (Throwable th) {
            Trace.endSection();
            throw th;
        }
    }

    @Override // androidx.compose.runtime.InterfaceC0819s
    public final void dispose() {
        synchronized (this.d) {
            try {
                if (this.s.E) {
                    AbstractC0805k0.b("Composition is disposed while composing. If dispose is triggered by a call in @Composable function, consider wrapping it with SideEffect block.");
                }
                if (!this.t) {
                    this.t = true;
                    androidx.compose.runtime.internal.d dVar = AbstractC0800i.b;
                    C0778a c0778a = this.s.K;
                    if (c0778a != null) {
                        h(c0778a);
                    }
                    boolean z = this.f.b > 0;
                    if (z || !this.e.a.g()) {
                        androidx.compose.runtime.internal.j jVar = new androidx.compose.runtime.internal.j(this.e);
                        if (z) {
                            D0 d0G = this.f.g();
                            try {
                                r.h(d0G, jVar);
                                Unit unit = Unit.a;
                                d0G.e(true);
                                this.b.b();
                                this.b.k();
                                jVar.d();
                            } catch (Throwable th) {
                                d0G.e(false);
                                throw th;
                            }
                        }
                        jVar.c();
                    }
                    C0814p c0814p = this.s;
                    c0814p.getClass();
                    Trace.beginSection("Compose:Composer.dispose");
                    try {
                        c0814p.b.r(c0814p);
                        c0814p.D.clear();
                        c0814p.r.clear();
                        c0814p.e.b.b();
                        c0814p.u = null;
                        c0814p.a.b();
                        Unit unit2 = Unit.a;
                        Trace.endSection();
                    } catch (Throwable th2) {
                        Trace.endSection();
                        throw th2;
                    }
                }
                Unit unit3 = Unit.a;
            } catch (Throwable th3) {
                throw th3;
            }
        }
        this.a.s(this);
    }

    /* JADX WARN: Removed duplicated region for block: B:24:0x006c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void e(java.lang.Object r20, boolean r21) {
        /*
            r19 = this;
            r0 = r19
            r1 = r20
            androidx.collection.I r2 = r0.g
            java.lang.Object r2 = r2.f(r1)
            if (r2 == 0) goto L9a
            boolean r3 = r2 instanceof androidx.collection.J
            androidx.collection.J r4 = r0.h
            androidx.collection.J r5 = r0.i
            androidx.collection.I r6 = r0.m
            if (r3 == 0) goto L7d
            androidx.collection.J r2 = (androidx.collection.J) r2
            java.lang.Object[] r3 = r2.b
            long[] r2 = r2.a
            int r7 = r2.length
            int r7 = r7 + (-2)
            if (r7 < 0) goto L9a
            r9 = 0
        L22:
            r10 = r2[r9]
            long r12 = ~r10
            r14 = 7
            long r12 = r12 << r14
            long r12 = r12 & r10
            r14 = -9187201950435737472(0x8080808080808080, double:-2.937446524422997E-306)
            long r12 = r12 & r14
            int r12 = (r12 > r14 ? 1 : (r12 == r14 ? 0 : -1))
            if (r12 == 0) goto L78
            int r12 = r9 - r7
            int r12 = ~r12
            int r12 = r12 >>> 31
            r13 = 8
            int r12 = 8 - r12
            r14 = 0
        L3c:
            if (r14 >= r12) goto L75
            r15 = 255(0xff, double:1.26E-321)
            long r15 = r15 & r10
            r17 = 128(0x80, double:6.3E-322)
            int r15 = (r15 > r17 ? 1 : (r15 == r17 ? 0 : -1))
            if (r15 >= 0) goto L6c
            int r15 = r9 << 3
            int r15 = r15 + r14
            r15 = r3[r15]
            androidx.compose.runtime.o0 r15 = (androidx.compose.runtime.C0813o0) r15
            boolean r16 = com.google.android.gms.internal.mlkit_vision_barcode.F4.d(r6, r1, r15)
            if (r16 != 0) goto L6c
            androidx.compose.runtime.P r8 = r15.c(r1)
            r17 = r13
            androidx.compose.runtime.P r13 = androidx.compose.runtime.P.a
            if (r8 == r13) goto L6e
            androidx.collection.I r8 = r15.g
            if (r8 == 0) goto L68
            if (r21 != 0) goto L68
            r5.a(r15)
            goto L6e
        L68:
            r4.a(r15)
            goto L6e
        L6c:
            r17 = r13
        L6e:
            long r10 = r10 >> r17
            int r14 = r14 + 1
            r13 = r17
            goto L3c
        L75:
            r8 = r13
            if (r12 != r8) goto L9a
        L78:
            if (r9 == r7) goto L9a
            int r9 = r9 + 1
            goto L22
        L7d:
            androidx.compose.runtime.o0 r2 = (androidx.compose.runtime.C0813o0) r2
            boolean r3 = com.google.android.gms.internal.mlkit_vision_barcode.F4.d(r6, r1, r2)
            if (r3 != 0) goto L9a
            androidx.compose.runtime.P r1 = r2.c(r1)
            androidx.compose.runtime.P r3 = androidx.compose.runtime.P.a
            if (r1 == r3) goto L9a
            androidx.collection.I r1 = r2.g
            if (r1 == 0) goto L97
            if (r21 != 0) goto L97
            r5.a(r2)
            return
        L97:
            r4.a(r2)
        L9a:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.C0833w.e(java.lang.Object, boolean):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:110:0x023c  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x0183 A[EDGE_INSN: B:73:0x0183->B:224:0x0122 BREAK  A[LOOP:13: B:63:0x0151->B:74:0x0185]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void f(java.util.Set r35, boolean r36) {
        /*
            Method dump skipped, instructions count: 942
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.C0833w.f(java.util.Set, boolean):void");
    }

    public final void g() {
        synchronized (this.d) {
            try {
                h(this.k);
                p();
                Unit unit = Unit.a;
            } catch (Throwable th) {
                try {
                    try {
                        if (!this.e.a.g()) {
                            androidx.collection.M m = this.e;
                            new ArrayList();
                            if (!m.a.g()) {
                                Trace.beginSection("Compose:abandons");
                                try {
                                    androidx.collection.L l = new androidx.collection.L(m);
                                    while (((kotlin.sequences.h) l.c).hasNext()) {
                                        InterfaceC0834w0 interfaceC0834w0 = (InterfaceC0834w0) ((kotlin.sequences.h) l.c).next();
                                        l.remove();
                                        interfaceC0834w0.a();
                                    }
                                    Unit unit2 = Unit.a;
                                    Trace.endSection();
                                } catch (Throwable th2) {
                                    Trace.endSection();
                                    throw th2;
                                }
                            }
                        }
                        throw th;
                    } catch (Exception e) {
                        d();
                        throw e;
                    }
                } catch (Throwable th3) {
                    throw th3;
                }
            }
        }
    }

    /* JADX WARN: Finally extract failed */
    public final void h(C0778a c0778a) throws Throwable {
        androidx.compose.runtime.internal.j jVar;
        boolean z;
        long[] jArr;
        int i;
        androidx.compose.runtime.internal.j jVar2;
        long[] jArr2;
        long j;
        char c;
        long j2;
        int i2;
        boolean zG;
        int i3;
        boolean z2 = true;
        C0778a c0778a2 = this.l;
        androidx.compose.runtime.internal.j jVar3 = new androidx.compose.runtime.internal.j(this.e);
        try {
            if (c0778a.b.d()) {
                if (c0778a2.b.d()) {
                    jVar3.c();
                    return;
                }
                return;
            }
            try {
                Trace.beginSection("Compose:applyChanges");
                try {
                    AbstractC0772a abstractC0772a = this.b;
                    D0 d0G = this.f.g();
                    int i4 = 0;
                    try {
                        c0778a.b(abstractC0772a, d0G, jVar3);
                        Unit unit = Unit.a;
                        d0G.e(true);
                        abstractC0772a.k();
                        Trace.endSection();
                        jVar3.d();
                        androidx.compose.runtime.collection.b bVar = (androidx.compose.runtime.collection.b) jVar3.e;
                        if (bVar.c != 0) {
                            Trace.beginSection("Compose:sideeffects");
                            try {
                                Object[] objArr = bVar.a;
                                int i5 = bVar.c;
                                for (int i6 = 0; i6 < i5; i6++) {
                                    ((Function0) objArr[i6]).invoke();
                                }
                                bVar.i();
                                Unit unit2 = Unit.a;
                                Trace.endSection();
                            } catch (Throwable th) {
                                Trace.endSection();
                                throw th;
                            }
                        }
                        if (this.o) {
                            Trace.beginSection("Compose:unobserve");
                            try {
                                this.o = false;
                                androidx.collection.I i7 = this.g;
                                long[] jArr3 = i7.a;
                                int length = jArr3.length - 2;
                                if (length >= 0) {
                                    int i8 = 0;
                                    while (true) {
                                        long j3 = jArr3[i8];
                                        char c2 = 7;
                                        long j4 = -9187201950435737472L;
                                        if ((((~j3) << 7) & j3 & (-9187201950435737472L)) != -9187201950435737472L) {
                                            int i9 = 8;
                                            int i10 = 8 - ((~(i8 - length)) >>> 31);
                                            z = z2;
                                            int i11 = i4;
                                            while (i11 < i10) {
                                                if ((j3 & 255) < 128) {
                                                    c = c2;
                                                    int i12 = (i8 << 3) + i11;
                                                    j2 = j4;
                                                    Object obj = i7.b[i12];
                                                    Object obj2 = i7.c[i12];
                                                    if (obj2 instanceof androidx.collection.J) {
                                                        Intrinsics.e(obj2, "null cannot be cast to non-null type androidx.collection.MutableScatterSet<Scope of androidx.compose.runtime.collection.ScopeMap>");
                                                        androidx.collection.J j5 = (androidx.collection.J) obj2;
                                                        Object[] objArr2 = j5.b;
                                                        long[] jArr4 = j5.a;
                                                        int i13 = i9;
                                                        int length2 = jArr4.length - 2;
                                                        if (length2 >= 0) {
                                                            jVar2 = jVar3;
                                                            jArr2 = jArr3;
                                                            int i14 = 0;
                                                            while (true) {
                                                                try {
                                                                    long j6 = jArr4[i14];
                                                                    j = j3;
                                                                    if ((((~j6) << c) & j6 & j2) != j2) {
                                                                        int i15 = 8 - ((~(i14 - length2)) >>> 31);
                                                                        int i16 = 0;
                                                                        while (i16 < i15) {
                                                                            if ((j6 & 255) < 128) {
                                                                                i3 = i11;
                                                                                int i17 = (i14 << 3) + i16;
                                                                                if (!((C0813o0) objArr2[i17]).b()) {
                                                                                    j5.k(i17);
                                                                                }
                                                                            } else {
                                                                                i3 = i11;
                                                                            }
                                                                            j6 >>= i13;
                                                                            i16++;
                                                                            i11 = i3;
                                                                        }
                                                                        i = i11;
                                                                        if (i15 != i13) {
                                                                            break;
                                                                        }
                                                                    } else {
                                                                        i = i11;
                                                                    }
                                                                    if (i14 == length2) {
                                                                        break;
                                                                    }
                                                                    i14++;
                                                                    j3 = j;
                                                                    i11 = i;
                                                                    i13 = 8;
                                                                } catch (Throwable th2) {
                                                                    th = th2;
                                                                    Trace.endSection();
                                                                    throw th;
                                                                }
                                                            }
                                                        } else {
                                                            i = i11;
                                                            jVar2 = jVar3;
                                                            jArr2 = jArr3;
                                                            j = j3;
                                                        }
                                                        zG = j5.g();
                                                    } else {
                                                        i = i11;
                                                        jVar2 = jVar3;
                                                        jArr2 = jArr3;
                                                        j = j3;
                                                        Intrinsics.e(obj2, "null cannot be cast to non-null type Scope of androidx.compose.runtime.collection.ScopeMap");
                                                        zG = !((C0813o0) obj2).b() ? z : false;
                                                    }
                                                    if (zG) {
                                                        i7.i(i12);
                                                    }
                                                    i2 = 8;
                                                } else {
                                                    i = i11;
                                                    jVar2 = jVar3;
                                                    jArr2 = jArr3;
                                                    j = j3;
                                                    c = c2;
                                                    j2 = j4;
                                                    i2 = i9;
                                                }
                                                j3 = j >> i2;
                                                c2 = c;
                                                i9 = i2;
                                                j4 = j2;
                                                jVar3 = jVar2;
                                                jArr3 = jArr2;
                                                i11 = i + 1;
                                            }
                                            jVar = jVar3;
                                            jArr = jArr3;
                                            if (i10 != i9) {
                                                break;
                                            }
                                        } else {
                                            z = z2;
                                            jVar = jVar3;
                                            jArr = jArr3;
                                        }
                                        if (i8 == length) {
                                            break;
                                        }
                                        i8++;
                                        z2 = z;
                                        jVar3 = jVar;
                                        jArr3 = jArr;
                                        i4 = 0;
                                    }
                                } else {
                                    jVar = jVar3;
                                }
                                k();
                                Unit unit3 = Unit.a;
                                Trace.endSection();
                            } catch (Throwable th3) {
                                th = th3;
                            }
                        } else {
                            jVar = jVar3;
                        }
                        if (c0778a2.b.d()) {
                            jVar.c();
                        }
                    } catch (Throwable th4) {
                        try {
                            d0G.e(false);
                            throw th4;
                        } catch (Throwable th5) {
                            th = th5;
                            Trace.endSection();
                            throw th;
                        }
                    }
                } catch (Throwable th6) {
                    th = th6;
                }
            } catch (Throwable th7) {
                th = th7;
                if (c0778a2.b.d()) {
                    jVar3.c();
                }
                throw th;
            }
        } catch (Throwable th8) {
            th = th8;
        }
    }

    public final void i() {
        synchronized (this.d) {
            try {
                if (this.l.b.e()) {
                    h(this.l);
                }
                Unit unit = Unit.a;
            } catch (Throwable th) {
                try {
                    try {
                        if (!this.e.a.g()) {
                            androidx.collection.M m = this.e;
                            new ArrayList();
                            if (!m.a.g()) {
                                Trace.beginSection("Compose:abandons");
                                try {
                                    androidx.collection.L l = new androidx.collection.L(m);
                                    while (((kotlin.sequences.h) l.c).hasNext()) {
                                        InterfaceC0834w0 interfaceC0834w0 = (InterfaceC0834w0) ((kotlin.sequences.h) l.c).next();
                                        l.remove();
                                        interfaceC0834w0.a();
                                    }
                                    Unit unit2 = Unit.a;
                                    Trace.endSection();
                                } catch (Throwable th2) {
                                    Trace.endSection();
                                    throw th2;
                                }
                            }
                        }
                        throw th;
                    } catch (Throwable th3) {
                        throw th3;
                    }
                } catch (Exception e) {
                    d();
                    throw e;
                }
            }
        }
    }

    public final void j() {
        synchronized (this.d) {
            try {
                this.s.u = null;
                if (!this.e.a.g()) {
                    androidx.collection.M m = this.e;
                    new ArrayList();
                    if (!m.a.g()) {
                        Trace.beginSection("Compose:abandons");
                        try {
                            androidx.collection.L l = new androidx.collection.L(m);
                            while (((kotlin.sequences.h) l.c).hasNext()) {
                                InterfaceC0834w0 interfaceC0834w0 = (InterfaceC0834w0) ((kotlin.sequences.h) l.c).next();
                                l.remove();
                                interfaceC0834w0.a();
                            }
                            Unit unit = Unit.a;
                            Trace.endSection();
                        } finally {
                        }
                    }
                }
                Unit unit2 = Unit.a;
            } catch (Throwable th) {
                try {
                    try {
                        if (!this.e.a.g()) {
                            androidx.collection.M m2 = this.e;
                            new ArrayList();
                            if (!m2.a.g()) {
                                Trace.beginSection("Compose:abandons");
                                try {
                                    androidx.collection.L l2 = new androidx.collection.L(m2);
                                    while (((kotlin.sequences.h) l2.c).hasNext()) {
                                        InterfaceC0834w0 interfaceC0834w02 = (InterfaceC0834w0) ((kotlin.sequences.h) l2.c).next();
                                        l2.remove();
                                        interfaceC0834w02.a();
                                    }
                                    Unit unit3 = Unit.a;
                                    Trace.endSection();
                                } finally {
                                }
                            }
                        }
                        throw th;
                    } catch (Throwable th2) {
                        throw th2;
                    }
                } catch (Exception e) {
                    d();
                    throw e;
                }
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:29:0x00a4  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void k() {
        /*
            Method dump skipped, instructions count: 387
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.C0833w.k():void");
    }

    public final void l(androidx.compose.runtime.internal.d dVar) throws Exception {
        try {
            synchronized (this.d) {
                o();
                androidx.collection.I i = this.n;
                this.n = F4.c();
                try {
                    this.r.getClass();
                    this.a.getClass();
                    C0814p c0814p = this.s;
                    if (!c0814p.e.b.d()) {
                        r.c("Expected applyChanges() to have been called");
                    }
                    c0814p.n(i, dVar);
                } catch (Exception e) {
                    this.n = i;
                    throw e;
                }
            }
        } catch (Throwable th) {
            try {
                if (!this.e.a.g()) {
                    androidx.collection.M m = this.e;
                    new ArrayList();
                    if (!m.a.g()) {
                        Trace.beginSection("Compose:abandons");
                        try {
                            androidx.collection.L l = new androidx.collection.L(m);
                            while (((kotlin.sequences.h) l.c).hasNext()) {
                                InterfaceC0834w0 interfaceC0834w0 = (InterfaceC0834w0) ((kotlin.sequences.h) l.c).next();
                                l.remove();
                                interfaceC0834w0.a();
                            }
                            Unit unit = Unit.a;
                            Trace.endSection();
                        } catch (Throwable th2) {
                            Trace.endSection();
                            throw th2;
                        }
                    }
                }
                throw th;
            } catch (Exception e2) {
                d();
                throw e2;
            }
        }
    }

    public final void m(androidx.compose.runtime.internal.d dVar) {
        if (this.t) {
            AbstractC0805k0.b("The composition is disposed");
        }
        this.a.a(this, dVar);
    }

    public final void n() {
        synchronized (this.d) {
            try {
                boolean z = this.f.b > 0;
                if (z || !this.e.a.g()) {
                    Trace.beginSection("Compose:deactivate");
                    try {
                        androidx.compose.runtime.internal.j jVar = new androidx.compose.runtime.internal.j(this.e);
                        if (z) {
                            D0 d0G = this.f.g();
                            try {
                                r.e(d0G, jVar);
                                Unit unit = Unit.a;
                                d0G.e(true);
                                this.b.k();
                                jVar.d();
                            } catch (Throwable th) {
                                d0G.e(false);
                                throw th;
                            }
                        }
                        jVar.c();
                        Unit unit2 = Unit.a;
                        Trace.endSection();
                    } catch (Throwable th2) {
                        Trace.endSection();
                        throw th2;
                    }
                }
                this.g.a();
                this.j.a();
                this.n.a();
                this.k.b.b();
                this.l.b.b();
                C0814p c0814p = this.s;
                c0814p.D.clear();
                c0814p.r.clear();
                c0814p.e.b.b();
                c0814p.u = null;
                Unit unit3 = Unit.a;
            } catch (Throwable th3) {
                throw th3;
            }
        }
    }

    public final void o() {
        AtomicReference atomicReference = this.c;
        Object obj = C0776c.a;
        Object andSet = atomicReference.getAndSet(obj);
        if (andSet != null) {
            if (andSet.equals(obj)) {
                r.d("pending composition has not been applied");
                throw new KotlinNothingValueException();
            }
            if (andSet instanceof Set) {
                f((Set) andSet, true);
                return;
            }
            if (!(andSet instanceof Object[])) {
                r.d("corrupt pendingModifications drain: " + atomicReference);
                throw new KotlinNothingValueException();
            }
            for (Set set : (Set[]) andSet) {
                f(set, true);
            }
        }
    }

    public final void p() {
        AtomicReference atomicReference = this.c;
        Object andSet = atomicReference.getAndSet(null);
        if (Intrinsics.b(andSet, C0776c.a)) {
            return;
        }
        if (andSet instanceof Set) {
            f((Set) andSet, false);
            return;
        }
        if (andSet instanceof Object[]) {
            for (Set set : (Set[]) andSet) {
                f(set, false);
            }
            return;
        }
        if (andSet == null) {
            r.d("calling recordModificationsOf and applyChanges concurrently is not supported");
            throw new KotlinNothingValueException();
        }
        r.d("corrupt pendingModifications drain: " + atomicReference);
        throw new KotlinNothingValueException();
    }

    public final void q() {
        AtomicReference atomicReference = this.c;
        Object andSet = atomicReference.getAndSet(kotlin.collections.M.a);
        if (Intrinsics.b(andSet, C0776c.a) || andSet == null) {
            return;
        }
        if (andSet instanceof Set) {
            f((Set) andSet, false);
            return;
        }
        if (!(andSet instanceof Object[])) {
            r.d("corrupt pendingModifications drain: " + atomicReference);
            throw new KotlinNothingValueException();
        }
        for (Set set : (Set[]) andSet) {
            f(set, false);
        }
    }

    public final void r(ArrayList arrayList) throws Exception {
        int size = arrayList.size();
        int i = 0;
        while (true) {
            if (i < size) {
                if (!((Z) ((Pair) arrayList.get(i)).a).c.equals(this)) {
                    r.c("Check failed");
                    break;
                }
                i++;
            }
        }
        try {
            C0814p c0814p = this.s;
            c0814p.getClass();
            try {
                c0814p.y(arrayList);
                c0814p.i();
                Unit unit = Unit.a;
            } catch (Throwable th) {
                c0814p.a();
                throw th;
            }
        } catch (Throwable th2) {
            androidx.collection.M m = this.e;
            try {
                if (!m.a.g()) {
                    new ArrayList();
                    if (!m.a.g()) {
                        Trace.beginSection("Compose:abandons");
                        try {
                            androidx.collection.L l = new androidx.collection.L(m);
                            kotlin.sequences.h hVar = (kotlin.sequences.h) l.c;
                            while (hVar.hasNext()) {
                                InterfaceC0834w0 interfaceC0834w0 = (InterfaceC0834w0) hVar.next();
                                l.remove();
                                interfaceC0834w0.a();
                            }
                            Unit unit2 = Unit.a;
                            Trace.endSection();
                        } catch (Throwable th3) {
                            Trace.endSection();
                            throw th3;
                        }
                    }
                }
                throw th2;
            } catch (Exception e) {
                d();
                throw e;
            }
        }
    }

    public final void s() {
        InterfaceC0815p0 interfaceC0815p0;
        synchronized (this.d) {
            try {
                for (Object obj : this.f.c) {
                    C0813o0 c0813o0 = obj instanceof C0813o0 ? (C0813o0) obj : null;
                    if (c0813o0 != null && (interfaceC0815p0 = c0813o0.b) != null) {
                        interfaceC0815p0.b(c0813o0, null);
                    }
                }
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:20:0x003f  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x00d5  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x00df A[Catch: all -> 0x0042, EDGE_INSN: B:81:0x00df->B:66:0x00df BREAK  A[LOOP:0: B:48:0x0096->B:62:0x00d7], EDGE_INSN: B:82:0x00df->B:66:0x00df BREAK  A[LOOP:0: B:48:0x0096->B:62:0x00d7], TRY_LEAVE, TryCatch #0 {all -> 0x0042, blocks: (B:4:0x000b, B:6:0x0010, B:8:0x0018, B:10:0x001f, B:14:0x0029, B:16:0x002f, B:13:0x0024, B:25:0x0047, B:27:0x004d, B:32:0x0058, B:35:0x005c, B:37:0x0068, B:38:0x0071, B:40:0x0075, B:41:0x007e, B:43:0x0086, B:45:0x008a, B:48:0x0096, B:50:0x00a6, B:52:0x00b2, B:54:0x00bc, B:58:0x00cb, B:62:0x00d7, B:63:0x00da, B:66:0x00df), top: B:79:0x000b }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final androidx.compose.runtime.P t(androidx.compose.runtime.C0813o0 r21, androidx.compose.runtime.C0774b r22, java.lang.Object r23) {
        /*
            Method dump skipped, instructions count: 255
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.C0833w.t(androidx.compose.runtime.o0, androidx.compose.runtime.b, java.lang.Object):androidx.compose.runtime.P");
    }

    public final void u(Object obj) {
        Object objF = this.g.f(obj);
        if (objF == null) {
            return;
        }
        boolean z = objF instanceof androidx.collection.J;
        androidx.collection.I i = this.m;
        if (!z) {
            C0813o0 c0813o0 = (C0813o0) objF;
            if (c0813o0.c(obj) == P.d) {
                F4.b(i, obj, c0813o0);
                return;
            }
            return;
        }
        androidx.collection.J j = (androidx.collection.J) objF;
        Object[] objArr = j.b;
        long[] jArr = j.a;
        int length = jArr.length - 2;
        if (length < 0) {
            return;
        }
        int i2 = 0;
        while (true) {
            long j2 = jArr[i2];
            if ((((~j2) << 7) & j2 & (-9187201950435737472L)) != -9187201950435737472L) {
                int i3 = 8 - ((~(i2 - length)) >>> 31);
                for (int i4 = 0; i4 < i3; i4++) {
                    if ((255 & j2) < 128) {
                        C0813o0 c0813o02 = (C0813o0) objArr[(i2 << 3) + i4];
                        if (c0813o02.c(obj) == P.d) {
                            F4.b(i, obj, c0813o02);
                        }
                    }
                    j2 >>= 8;
                }
                if (i3 != 8) {
                    return;
                }
            }
            if (i2 == length) {
                return;
            } else {
                i2++;
            }
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:17:0x0052, code lost:
    
        return true;
     */
    /* JADX WARN: Removed duplicated region for block: B:20:0x0059  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean v(java.util.Set r19) {
        /*
            r18 = this;
            r0 = r18
            r1 = r19
            boolean r2 = r1 instanceof androidx.compose.runtime.collection.e
            androidx.collection.I r3 = r0.j
            androidx.collection.I r4 = r0.g
            r5 = 0
            r6 = 1
            if (r2 == 0) goto L5e
            androidx.compose.runtime.collection.e r1 = (androidx.compose.runtime.collection.e) r1
            androidx.collection.J r1 = r1.a
            java.lang.Object[] r2 = r1.b
            long[] r1 = r1.a
            int r7 = r1.length
            int r7 = r7 + (-2)
            if (r7 < 0) goto L7b
            r8 = r5
        L1c:
            r9 = r1[r8]
            long r11 = ~r9
            r13 = 7
            long r11 = r11 << r13
            long r11 = r11 & r9
            r13 = -9187201950435737472(0x8080808080808080, double:-2.937446524422997E-306)
            long r11 = r11 & r13
            int r11 = (r11 > r13 ? 1 : (r11 == r13 ? 0 : -1))
            if (r11 == 0) goto L59
            int r11 = r8 - r7
            int r11 = ~r11
            int r11 = r11 >>> 31
            r12 = 8
            int r11 = 8 - r11
            r13 = r5
        L36:
            if (r13 >= r11) goto L57
            r14 = 255(0xff, double:1.26E-321)
            long r14 = r14 & r9
            r16 = 128(0x80, double:6.3E-322)
            int r14 = (r14 > r16 ? 1 : (r14 == r16 ? 0 : -1))
            if (r14 >= 0) goto L53
            int r14 = r8 << 3
            int r14 = r14 + r13
            r14 = r2[r14]
            boolean r15 = r4.c(r14)
            if (r15 != 0) goto L52
            boolean r14 = r3.c(r14)
            if (r14 == 0) goto L53
        L52:
            return r6
        L53:
            long r9 = r9 >> r12
            int r13 = r13 + 1
            goto L36
        L57:
            if (r11 != r12) goto L7b
        L59:
            if (r8 == r7) goto L7b
            int r8 = r8 + 1
            goto L1c
        L5e:
            java.lang.Iterable r1 = (java.lang.Iterable) r1
            java.util.Iterator r1 = r1.iterator()
        L64:
            boolean r2 = r1.hasNext()
            if (r2 == 0) goto L7b
            java.lang.Object r2 = r1.next()
            boolean r7 = r4.c(r2)
            if (r7 != 0) goto L7a
            boolean r2 = r3.c(r2)
            if (r2 == 0) goto L64
        L7a:
            return r6
        L7b:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.C0833w.v(java.util.Set):boolean");
    }

    public final boolean w() {
        boolean zC;
        synchronized (this.d) {
            try {
                o();
                try {
                    androidx.collection.I i = this.n;
                    this.n = F4.c();
                    try {
                        this.r.getClass();
                        this.a.getClass();
                        zC = this.s.C(i);
                        if (!zC) {
                            p();
                        }
                    } catch (Exception e) {
                        this.n = i;
                        throw e;
                    }
                } catch (Throwable th) {
                    try {
                        if (!this.e.a.g()) {
                            androidx.collection.M m = this.e;
                            new ArrayList();
                            if (!m.a.g()) {
                                Trace.beginSection("Compose:abandons");
                                try {
                                    androidx.collection.L l = new androidx.collection.L(m);
                                    while (((kotlin.sequences.h) l.c).hasNext()) {
                                        InterfaceC0834w0 interfaceC0834w0 = (InterfaceC0834w0) ((kotlin.sequences.h) l.c).next();
                                        l.remove();
                                        interfaceC0834w0.a();
                                    }
                                    Unit unit = Unit.a;
                                    Trace.endSection();
                                } catch (Throwable th2) {
                                    Trace.endSection();
                                    throw th2;
                                }
                            }
                        }
                        throw th;
                    } catch (Exception e2) {
                        d();
                        throw e2;
                    }
                }
            } catch (Throwable th3) {
                throw th3;
            }
        }
        return zC;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v10, types: [java.util.Set[]] */
    /* JADX WARN: Type inference failed for: r2v8, types: [java.lang.Object[]] */
    public final void x(androidx.compose.runtime.collection.e eVar) {
        androidx.compose.runtime.collection.e eVar2;
        while (true) {
            Object obj = this.c.get();
            if (obj == null ? true : obj.equals(C0776c.a)) {
                eVar2 = eVar;
            } else if (obj instanceof Set) {
                eVar2 = new Set[]{obj, eVar};
            } else {
                if (!(obj instanceof Object[])) {
                    throw new IllegalStateException(("corrupt pendingModifications: " + this.c).toString());
                }
                Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.Array<kotlin.collections.Set<kotlin.Any>>");
                Set[] setArr = (Set[]) obj;
                Intrinsics.checkNotNullParameter(setArr, "<this>");
                int length = setArr.length;
                ?? CopyOf = Arrays.copyOf(setArr, length + 1);
                CopyOf[length] = eVar;
                eVar2 = CopyOf;
            }
            AtomicReference atomicReference = this.c;
            while (!atomicReference.compareAndSet(obj, eVar2)) {
                if (atomicReference.get() != obj) {
                    break;
                }
            }
            if (obj == null) {
                synchronized (this.d) {
                    p();
                    Unit unit = Unit.a;
                }
                return;
            }
            return;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:22:0x0057  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void y(java.lang.Object r15) {
        /*
            r14 = this;
            java.lang.Object r0 = r14.d
            monitor-enter(r0)
            r14.u(r15)     // Catch: java.lang.Throwable -> L4f
            androidx.collection.I r1 = r14.j     // Catch: java.lang.Throwable -> L4f
            java.lang.Object r15 = r1.f(r15)     // Catch: java.lang.Throwable -> L4f
            if (r15 == 0) goto L61
            boolean r1 = r15 instanceof androidx.collection.J     // Catch: java.lang.Throwable -> L4f
            if (r1 == 0) goto L5c
            androidx.collection.J r15 = (androidx.collection.J) r15     // Catch: java.lang.Throwable -> L4f
            java.lang.Object[] r1 = r15.b     // Catch: java.lang.Throwable -> L4f
            long[] r15 = r15.a     // Catch: java.lang.Throwable -> L4f
            int r2 = r15.length     // Catch: java.lang.Throwable -> L4f
            int r2 = r2 + (-2)
            if (r2 < 0) goto L61
            r3 = 0
            r4 = r3
        L1f:
            r5 = r15[r4]     // Catch: java.lang.Throwable -> L4f
            long r7 = ~r5     // Catch: java.lang.Throwable -> L4f
            r9 = 7
            long r7 = r7 << r9
            long r7 = r7 & r5
            r9 = -9187201950435737472(0x8080808080808080, double:-2.937446524422997E-306)
            long r7 = r7 & r9
            int r7 = (r7 > r9 ? 1 : (r7 == r9 ? 0 : -1))
            if (r7 == 0) goto L57
            int r7 = r4 - r2
            int r7 = ~r7     // Catch: java.lang.Throwable -> L4f
            int r7 = r7 >>> 31
            r8 = 8
            int r7 = 8 - r7
            r9 = r3
        L39:
            if (r9 >= r7) goto L55
            r10 = 255(0xff, double:1.26E-321)
            long r10 = r10 & r5
            r12 = 128(0x80, double:6.3E-322)
            int r10 = (r10 > r12 ? 1 : (r10 == r12 ? 0 : -1))
            if (r10 >= 0) goto L51
            int r10 = r4 << 3
            int r10 = r10 + r9
            r10 = r1[r10]     // Catch: java.lang.Throwable -> L4f
            androidx.compose.runtime.E r10 = (androidx.compose.runtime.E) r10     // Catch: java.lang.Throwable -> L4f
            r14.u(r10)     // Catch: java.lang.Throwable -> L4f
            goto L51
        L4f:
            r15 = move-exception
            goto L65
        L51:
            long r5 = r5 >> r8
            int r9 = r9 + 1
            goto L39
        L55:
            if (r7 != r8) goto L61
        L57:
            if (r4 == r2) goto L61
            int r4 = r4 + 1
            goto L1f
        L5c:
            androidx.compose.runtime.E r15 = (androidx.compose.runtime.E) r15     // Catch: java.lang.Throwable -> L4f
            r14.u(r15)     // Catch: java.lang.Throwable -> L4f
        L61:
            kotlin.Unit r15 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L4f
            monitor-exit(r0)
            return
        L65:
            monitor-exit(r0)
            throw r15
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.C0833w.y(java.lang.Object):void");
    }
}

package androidx.compose.runtime;

import android.os.Trace;
import androidx.collection.C0221t;
import androidx.collection.C0223v;
import androidx.compose.runtime.changelist.C0778a;
import androidx.compose.runtime.changelist.C0779b;
import androidx.compose.runtime.changelist.C0780c;
import androidx.compose.runtime.changelist.C0782e;
import com.google.android.gms.internal.mlkit_vision_barcode.D4;
import com.google.android.gms.internal.mlkit_vision_barcode.F4;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import java.util.ArrayList;
import java.util.Set;
import kotlin.Unit;
import kotlin.collections.C4930v;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.runtime.p, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0814p implements InterfaceC0806l {
    public int A;
    public boolean B;
    public final C0812o C;
    public final ArrayList D;
    public boolean E;
    public C0840z0 F;
    public A0 G;
    public D0 H;
    public boolean I;
    public InterfaceC0803j0 J;
    public C0778a K;
    public final C0779b L;
    public C0774b M;
    public C0780c N;
    public boolean O;
    public int P;
    public C0831v Q;
    public final AbstractC0772a a;
    public final AbstractC0827t b;
    public final A0 c;
    public final androidx.collection.M d;
    public final C0778a e;
    public final C0778a f;
    public final C0833w g;
    public C0801i0 i;
    public int j;
    public int k;
    public int l;
    public int[] n;
    public C0221t o;
    public boolean p;
    public boolean q;
    public C0223v u;
    public boolean v;
    public boolean x;
    public int z;
    public final ArrayList h = new ArrayList();
    public final N m = new N();
    public final ArrayList r = new ArrayList();
    public final N s = new N();
    public InterfaceC0803j0 t = androidx.compose.runtime.internal.i.e;
    public final N w = new N();
    public int y = -1;

    public C0814p(AbstractC0772a abstractC0772a, AbstractC0827t abstractC0827t, A0 a0, androidx.collection.M m, C0778a c0778a, C0778a c0778a2, C0833w c0833w) {
        this.a = abstractC0772a;
        this.b = abstractC0827t;
        this.c = a0;
        this.d = m;
        this.e = c0778a;
        this.f = c0778a2;
        this.g = c0833w;
        this.B = abstractC0827t.f() || abstractC0827t.d();
        this.C = new C0812o(this, 0);
        this.D = new ArrayList();
        C0840z0 c0840z0E = a0.e();
        c0840z0E.c();
        this.F = c0840z0E;
        A0 a02 = new A0();
        if (abstractC0827t.f()) {
            a02.b();
        }
        if (abstractC0827t.d()) {
            a02.k = new C0223v();
        }
        this.G = a02;
        D0 d0G = a02.g();
        d0G.e(true);
        this.H = d0G;
        this.L = new C0779b(this, c0778a);
        C0840z0 c0840z0E2 = this.G.e();
        try {
            C0774b c0774bA = c0840z0E2.a(0);
            c0840z0E2.c();
            this.M = c0774bA;
            this.N = new C0780c();
        } catch (Throwable th) {
            c0840z0E2.c();
            throw th;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x002e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final androidx.compose.runtime.Z K(androidx.compose.runtime.C0814p r14, int r15) {
        /*
            androidx.compose.runtime.z0 r0 = r14.F
            int r1 = r15 * 5
            int[] r2 = r0.b
            r3 = r2[r1]
            java.lang.Object r0 = r0.n(r2, r15)
            r2 = 126665345(0x78cc281, float:2.1179178E-34)
            r4 = 0
            if (r3 != r2) goto Lad
            boolean r0 = r0 instanceof androidx.compose.runtime.X
            if (r0 == 0) goto Lad
            androidx.compose.runtime.z0 r0 = r14.F
            boolean r0 = r0.d(r15)
            if (r0 == 0) goto L2e
            java.util.ArrayList r0 = new java.util.ArrayList
            r0.<init>()
            L(r14, r0, r15)
            boolean r2 = r0.isEmpty()
            if (r2 != 0) goto L2e
            r13 = r0
            goto L2f
        L2e:
            r13 = r4
        L2f:
            androidx.compose.runtime.z0 r0 = r14.F
            int[] r2 = r0.b
            java.lang.Object r0 = r0.n(r2, r15)
            java.lang.String r2 = "null cannot be cast to non-null type androidx.compose.runtime.MovableContent<kotlin.Any?>"
            kotlin.jvm.internal.Intrinsics.e(r0, r2)
            r6 = r0
            androidx.compose.runtime.X r6 = (androidx.compose.runtime.X) r6
            androidx.compose.runtime.z0 r0 = r14.F
            r2 = 0
            java.lang.Object r7 = r0.h(r15, r2)
            androidx.compose.runtime.z0 r0 = r14.F
            androidx.compose.runtime.b r10 = r0.a(r15)
            androidx.compose.runtime.z0 r0 = r14.F
            int[] r0 = r0.b
            int r1 = r1 + 3
            r0 = r0[r1]
            int r0 = r0 + r15
            java.util.ArrayList r1 = r14.r
            java.util.ArrayList r3 = new java.util.ArrayList
            r3.<init>()
            int r4 = androidx.compose.runtime.r.g(r15, r1)
            if (r4 >= 0) goto L65
            int r4 = r4 + 1
            int r4 = -r4
        L65:
            int r5 = r1.size()
            if (r4 >= r5) goto L7b
            java.lang.Object r5 = r1.get(r4)
            androidx.compose.runtime.O r5 = (androidx.compose.runtime.O) r5
            int r8 = r5.b
            if (r8 >= r0) goto L7b
            r3.add(r5)
            int r4 = r4 + 1
            goto L65
        L7b:
            java.util.ArrayList r11 = new java.util.ArrayList
            int r0 = r3.size()
            r11.<init>(r0)
            int r0 = r3.size()
        L88:
            if (r2 >= r0) goto L9f
            java.lang.Object r1 = r3.get(r2)
            androidx.compose.runtime.O r1 = (androidx.compose.runtime.O) r1
            androidx.compose.runtime.o0 r4 = r1.a
            java.lang.Object r1 = r1.c
            kotlin.Pair r5 = new kotlin.Pair
            r5.<init>(r4, r1)
            r11.add(r5)
            int r2 = r2 + 1
            goto L88
        L9f:
            androidx.compose.runtime.Z r5 = new androidx.compose.runtime.Z
            androidx.compose.runtime.j0 r12 = r14.m(r15)
            androidx.compose.runtime.w r8 = r14.g
            androidx.compose.runtime.A0 r9 = r14.c
            r5.<init>(r6, r7, r8, r9, r10, r11, r12, r13)
            return r5
        Lad:
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.C0814p.K(androidx.compose.runtime.p, int):androidx.compose.runtime.Z");
    }

    public static final void L(C0814p c0814p, ArrayList arrayList, int i) {
        int i2 = c0814p.F.b[(i * 5) + 3] + i;
        int i3 = i + 1;
        while (i3 < i2) {
            C0840z0 c0840z0 = c0814p.F;
            int i4 = i3 * 5;
            if ((c0840z0.b[i4 + 1] & 134217728) != 0) {
                Z zK = K(c0814p, i3);
                if (zK != null) {
                    arrayList.add(zK);
                }
            } else if (c0840z0.d(i3)) {
                L(c0814p, arrayList, i3);
            }
            i3 += c0814p.F.b[i4 + 3];
        }
    }

    public static final int M(C0814p c0814p, int i, int i2, boolean z, int i3) {
        C0840z0 c0840z0 = c0814p.F;
        int i4 = i2 * 5;
        int[] iArr = c0840z0.b;
        boolean z2 = (iArr[i4 + 1] & 134217728) != 0;
        C0779b c0779b = c0814p.L;
        if (z2) {
            int i5 = iArr[i4];
            Object objN = c0840z0.n(iArr, i2);
            AbstractC0827t abstractC0827t = c0814p.b;
            if (i5 == 126665345 && (objN instanceof X)) {
                Z zK = K(c0814p, i2);
                if (zK != null) {
                    abstractC0827t.b(zK);
                    c0779b.f();
                    C0778a c0778a = c0779b.b;
                    c0778a.getClass();
                    androidx.compose.runtime.changelist.w wVar = androidx.compose.runtime.changelist.w.c;
                    androidx.compose.runtime.changelist.L l = c0778a.b;
                    l.f(wVar);
                    D4.d(l, c0814p.g, c0814p.b, zK);
                }
                if (!z || i2 == i) {
                    return c0840z0.m(i2);
                }
                c0779b.d();
                c0779b.c();
                C0814p c0814p2 = c0779b.a;
                int iM = c0814p2.F.j(i2) ? 1 : c0814p2.F.m(i2);
                if (iM > 0) {
                    c0779b.g(i3, iM);
                }
                return 0;
            }
            if (i5 == 206 && Intrinsics.b(objN, r.e)) {
                Object objH = c0840z0.h(i2, 0);
                C0808m c0808m = objH instanceof C0808m ? (C0808m) objH : null;
                if (c0808m != null) {
                    for (C0814p c0814p3 : c0808m.a.e) {
                        A0 a0 = c0814p3.c;
                        if (a0.b > 0 && (a0.a[1] & 67108864) != 0) {
                            C0833w c0833w = c0814p3.g;
                            synchronized (c0833w.d) {
                                c0833w.q();
                                androidx.collection.I i6 = c0833w.n;
                                c0833w.n = F4.c();
                                try {
                                    c0833w.s.e0(i6);
                                    Unit unit = Unit.a;
                                } catch (Exception e) {
                                    c0833w.n = i6;
                                    throw e;
                                }
                            }
                            C0778a c0778a2 = new C0778a();
                            c0814p3.K = c0778a2;
                            C0840z0 c0840z0E = c0814p3.c.e();
                            try {
                                c0814p3.F = c0840z0E;
                                C0779b c0779b2 = c0814p3.L;
                                C0778a c0778a3 = c0779b2.b;
                                try {
                                    c0779b2.b = c0778a2;
                                    c0814p3.J(0);
                                    C0779b c0779b3 = c0814p3.L;
                                    c0779b3.c();
                                    if (c0779b3.c) {
                                        C0778a c0778a4 = c0779b3.b;
                                        c0778a4.getClass();
                                        c0778a4.b.f(androidx.compose.runtime.changelist.C.c);
                                        if (c0779b3.c) {
                                            c0779b3.e(false);
                                            c0779b3.e(false);
                                            C0778a c0778a5 = c0779b3.b;
                                            c0778a5.getClass();
                                            c0778a5.b.f(androidx.compose.runtime.changelist.m.c);
                                            c0779b3.c = false;
                                        }
                                    }
                                } finally {
                                }
                            } finally {
                                c0840z0E.c();
                            }
                        }
                        abstractC0827t.p(c0814p3.g);
                    }
                }
                return c0840z0.m(i2);
            }
            if (!c0840z0.j(i2)) {
                return c0840z0.m(i2);
            }
        } else if (c0840z0.d(i2)) {
            int i7 = iArr[i4 + 3] + i2;
            int iM2 = 0;
            for (int i8 = i2 + 1; i8 < i7; i8 += iArr[(i8 * 5) + 3]) {
                boolean zJ = c0840z0.j(i8);
                if (zJ) {
                    c0779b.d();
                    Object objL = c0840z0.l(i8);
                    c0779b.d();
                    c0779b.h.add(objL);
                }
                iM2 += M(c0814p, i, i8, zJ || z, zJ ? 0 : i3 + iM2);
                if (zJ) {
                    c0779b.d();
                    c0779b.b();
                }
            }
            if (!c0840z0.j(i2)) {
                return iM2;
            }
        } else if (!c0840z0.j(i2)) {
            return c0840z0.m(i2);
        }
        return 1;
    }

    public final Object A() {
        boolean z = this.O;
        V v = C0804k.a;
        if (!z) {
            Object objK = this.F.k();
            if (!this.x || (objK instanceof C0808m)) {
                return objK;
            }
        } else if (this.q) {
            r.c("A call to createNode(), emitNode() or useNode() expected");
            return v;
        }
        return v;
    }

    public final int B(int i) {
        int iO = this.F.o(i) + 1;
        int i2 = 0;
        while (iO < i) {
            if (!this.F.i(iO)) {
                i2++;
            }
            iO += C0.a(this.F.b, iO);
        }
        return i2;
    }

    public final boolean C(androidx.collection.I i) {
        androidx.compose.runtime.changelist.L l = this.e.b;
        if (!l.d()) {
            r.c("Expected applyChanges() to have been called");
        }
        if (i.e <= 0 && this.r.isEmpty()) {
            return false;
        }
        n(i, null);
        return l.e();
    }

    /* JADX WARN: Removed duplicated region for block: B:29:0x0059 A[Catch: all -> 0x0024, TRY_LEAVE, TryCatch #0 {all -> 0x0024, blocks: (B:3:0x0005, B:6:0x0012, B:8:0x0020, B:12:0x0029, B:11:0x0026, B:15:0x0030, B:18:0x0038, B:21:0x0040, B:23:0x0048, B:25:0x004e, B:26:0x0052, B:27:0x0053, B:29:0x0059, B:22:0x0044), top: B:34:0x0005, inners: #1 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object D(androidx.compose.runtime.C0833w r9, androidx.compose.runtime.C0833w r10, java.lang.Integer r11, java.util.List r12, kotlin.jvm.functions.Function0 r13) {
        /*
            r8 = this;
            boolean r0 = r8.E
            int r1 = r8.j
            r2 = 1
            r8.E = r2     // Catch: java.lang.Throwable -> L24
            r2 = 0
            r8.j = r2     // Catch: java.lang.Throwable -> L24
            int r3 = r12.size()     // Catch: java.lang.Throwable -> L24
            r4 = r2
        Lf:
            r5 = 0
            if (r4 >= r3) goto L2c
            java.lang.Object r6 = r12.get(r4)     // Catch: java.lang.Throwable -> L24
            kotlin.Pair r6 = (kotlin.Pair) r6     // Catch: java.lang.Throwable -> L24
            java.lang.Object r7 = r6.a     // Catch: java.lang.Throwable -> L24
            androidx.compose.runtime.o0 r7 = (androidx.compose.runtime.C0813o0) r7     // Catch: java.lang.Throwable -> L24
            java.lang.Object r6 = r6.b     // Catch: java.lang.Throwable -> L24
            if (r6 == 0) goto L26
            r8.d0(r7, r6)     // Catch: java.lang.Throwable -> L24
            goto L29
        L24:
            r9 = move-exception
            goto L62
        L26:
            r8.d0(r7, r5)     // Catch: java.lang.Throwable -> L24
        L29:
            int r4 = r4 + 1
            goto Lf
        L2c:
            if (r9 == 0) goto L59
            if (r11 == 0) goto L35
            int r11 = r11.intValue()     // Catch: java.lang.Throwable -> L24
            goto L36
        L35:
            r11 = -1
        L36:
            if (r10 == 0) goto L53
            boolean r12 = r10.equals(r9)     // Catch: java.lang.Throwable -> L24
            if (r12 != 0) goto L53
            if (r11 < 0) goto L53
            r9.p = r10     // Catch: java.lang.Throwable -> L24
            r9.q = r11     // Catch: java.lang.Throwable -> L24
            java.lang.Object r10 = r13.invoke()     // Catch: java.lang.Throwable -> L4d
            r9.p = r5     // Catch: java.lang.Throwable -> L24
            r9.q = r2     // Catch: java.lang.Throwable -> L24
            goto L57
        L4d:
            r10 = move-exception
            r9.p = r5     // Catch: java.lang.Throwable -> L24
            r9.q = r2     // Catch: java.lang.Throwable -> L24
            throw r10     // Catch: java.lang.Throwable -> L24
        L53:
            java.lang.Object r10 = r13.invoke()     // Catch: java.lang.Throwable -> L24
        L57:
            if (r10 != 0) goto L5d
        L59:
            java.lang.Object r10 = r13.invoke()     // Catch: java.lang.Throwable -> L24
        L5d:
            r8.E = r0
            r8.j = r1
            return r10
        L62:
            r8.E = r0
            r8.j = r1
            throw r9
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.C0814p.D(androidx.compose.runtime.w, androidx.compose.runtime.w, java.lang.Integer, java.util.List, kotlin.jvm.functions.Function0):java.lang.Object");
    }

    /* JADX WARN: Finally extract failed */
    /* JADX WARN: Removed duplicated region for block: B:10:0x003a  */
    /* JADX WARN: Removed duplicated region for block: B:120:0x021e  */
    /* JADX WARN: Removed duplicated region for block: B:123:0x0222  */
    /* JADX WARN: Removed duplicated region for block: B:126:0x0228  */
    /* JADX WARN: Removed duplicated region for block: B:127:0x0232  */
    /* JADX WARN: Removed duplicated region for block: B:129:0x0235  */
    /* JADX WARN: Removed duplicated region for block: B:141:0x0286  */
    /* JADX WARN: Removed duplicated region for block: B:176:0x0325  */
    /* JADX WARN: Removed duplicated region for block: B:179:0x032e  */
    /* JADX WARN: Removed duplicated region for block: B:182:0x033c  */
    /* JADX WARN: Removed duplicated region for block: B:195:0x027e A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00f1  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x00fc  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x0107  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void E() {
        /*
            Method dump skipped, instructions count: 897
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.C0814p.E():void");
    }

    public final void F() {
        J(this.F.g);
        C0779b c0779b = this.L;
        c0779b.e(false);
        c0779b.f();
        C0778a c0778a = c0779b.b;
        c0778a.getClass();
        c0778a.b.f(androidx.compose.runtime.changelist.y.c);
        int i = c0779b.f;
        C0840z0 c0840z0 = c0779b.a.F;
        c0779b.f = c0840z0.b[(c0840z0.g * 5) + 3] + i;
    }

    public final void G(InterfaceC0803j0 interfaceC0803j0) {
        C0223v c0223v = this.u;
        if (c0223v == null) {
            c0223v = new C0223v();
            this.u = c0223v;
        }
        c0223v.h(this.F.g, interfaceC0803j0);
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x001a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void H(int r7, int r8, int r9) {
        /*
            r6 = this;
            androidx.compose.runtime.z0 r0 = r6.F
            if (r7 != r8) goto L5
            goto L1a
        L5:
            if (r7 == r9) goto L6b
            if (r8 != r9) goto Lb
            goto L6b
        Lb:
            int r1 = r0.o(r7)
            if (r1 != r8) goto L14
            r9 = r8
            goto L6b
        L14:
            int r1 = r0.o(r8)
            if (r1 != r7) goto L1c
        L1a:
            r9 = r7
            goto L6b
        L1c:
            int r1 = r0.o(r7)
            int r2 = r0.o(r8)
            if (r1 != r2) goto L2b
            int r9 = r0.o(r7)
            goto L6b
        L2b:
            r1 = 0
            r2 = r7
            r3 = r1
        L2e:
            if (r2 <= 0) goto L39
            if (r2 == r9) goto L39
            int r2 = r0.o(r2)
            int r3 = r3 + 1
            goto L2e
        L39:
            r2 = r8
            r4 = r1
        L3b:
            if (r2 <= 0) goto L46
            if (r2 == r9) goto L46
            int r2 = r0.o(r2)
            int r4 = r4 + 1
            goto L3b
        L46:
            int r9 = r3 - r4
            r5 = r7
            r2 = r1
        L4a:
            if (r2 >= r9) goto L53
            int r5 = r0.o(r5)
            int r2 = r2 + 1
            goto L4a
        L53:
            int r4 = r4 - r3
            r9 = r8
        L55:
            if (r1 >= r4) goto L5e
            int r9 = r0.o(r9)
            int r1 = r1 + 1
            goto L55
        L5e:
            r1 = r9
            r9 = r5
        L60:
            if (r9 == r1) goto L6b
            int r9 = r0.o(r9)
            int r1 = r0.o(r1)
            goto L60
        L6b:
            if (r7 <= 0) goto L7f
            if (r7 == r9) goto L7f
            boolean r1 = r0.j(r7)
            if (r1 == 0) goto L7a
            androidx.compose.runtime.changelist.b r1 = r6.L
            r1.b()
        L7a:
            int r7 = r0.o(r7)
            goto L6b
        L7f:
            r6.o(r8, r9)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.C0814p.H(int, int, int):void");
    }

    public final Object I() {
        boolean z = this.O;
        V v = C0804k.a;
        if (!z) {
            Object objK = this.F.k();
            if (!this.x || (objK instanceof C0808m)) {
                return objK instanceof C0836x0 ? ((C0836x0) objK).a : objK;
            }
        } else if (this.q) {
            r.c("A call to createNode(), emitNode() or useNode() expected");
            return v;
        }
        return v;
    }

    public final void J(int i) {
        boolean zJ = this.F.j(i);
        C0779b c0779b = this.L;
        if (zJ) {
            c0779b.d();
            Object objL = this.F.l(i);
            c0779b.d();
            c0779b.h.add(objL);
        }
        M(this, i, i, zJ, 0);
        c0779b.d();
        if (zJ) {
            c0779b.b();
        }
    }

    public final boolean N(int i, boolean z) {
        return ((i & 1) == 0 && (this.O || this.x)) || z || !x();
    }

    /* JADX WARN: Removed duplicated region for block: B:27:0x008c  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x0098  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x00cc  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void O() {
        /*
            Method dump skipped, instructions count: 254
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.C0814p.O():void");
    }

    public final void P() {
        int i;
        C0840z0 c0840z0 = this.F;
        int i2 = c0840z0.i;
        if (i2 >= 0) {
            i = c0840z0.b[(i2 * 5) + 1] & 67108863;
        } else {
            i = 0;
        }
        this.k = i;
        c0840z0.r();
    }

    public final void Q() {
        if (this.k != 0) {
            r.c("No nodes can be emitted before calling skipAndEndGroup");
        }
        if (this.O) {
            return;
        }
        C0813o0 c0813o0V = v();
        if (c0813o0V != null) {
            int i = c0813o0V.a;
            if ((i & 128) == 0) {
                c0813o0V.a = i | 16;
            }
        }
        if (this.r.isEmpty()) {
            P();
        } else {
            E();
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:22:0x0067  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x006f  */
    /* JADX WARN: Removed duplicated region for block: B:26:0x0071  */
    /* JADX WARN: Removed duplicated region for block: B:29:0x0078  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00bf  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void R(java.lang.Object r26, int r27, java.lang.Object r28, int r29) {
        /*
            Method dump skipped, instructions count: 871
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.C0814p.R(java.lang.Object, int, java.lang.Object, int):void");
    }

    public final void S() {
        R(null, -127, null, 0);
    }

    public final void T(int i, C0791d0 c0791d0) {
        R(c0791d0, i, null, 0);
    }

    public final void U(int i, Object obj) {
        R(obj, i, null, 0);
    }

    public final void V() {
        R(null, 125, null, 1);
        this.q = true;
    }

    public final void W(Object obj, boolean z) {
        if (z) {
            C0840z0 c0840z0 = this.F;
            if (c0840z0.k <= 0) {
                if ((c0840z0.b[(c0840z0.g * 5) + 1] & 1073741824) == 0) {
                    AbstractC0805k0.a("Expected a node group");
                }
                c0840z0.s();
                return;
            }
            return;
        }
        if (obj != null && this.F.f() != obj) {
            C0779b c0779b = this.L;
            c0779b.getClass();
            c0779b.e(false);
            C0778a c0778a = c0779b.b;
            c0778a.getClass();
            androidx.compose.runtime.changelist.F f = androidx.compose.runtime.changelist.F.c;
            androidx.compose.runtime.changelist.L l = c0778a.b;
            l.f(f);
            D4.b(l, 0, obj);
        }
        this.F.s();
    }

    /* JADX WARN: Code restructure failed: missing block: B:18:0x0056, code lost:
    
        if ((r0.b[(r4 * 5) + 1] & 536870912) != 0) goto L22;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void X(int r10) {
        /*
            r9 = this;
            androidx.compose.runtime.i0 r0 = r9.i
            r1 = 0
            r2 = 0
            if (r0 == 0) goto La
            r9.R(r2, r10, r2, r1)
            return
        La:
            boolean r0 = r9.q
            if (r0 == 0) goto L13
            java.lang.String r0 = "A call to createNode(), emitNode() or useNode() expected"
            androidx.compose.runtime.r.c(r0)
        L13:
            int r0 = r9.l
            int r3 = r9.P
            r4 = 3
            int r3 = java.lang.Integer.rotateLeft(r3, r4)
            r3 = r3 ^ r10
            int r3 = java.lang.Integer.rotateLeft(r3, r4)
            r0 = r0 ^ r3
            r9.P = r0
            int r0 = r9.l
            r3 = 1
            int r0 = r0 + r3
            r9.l = r0
            androidx.compose.runtime.z0 r0 = r9.F
            boolean r4 = r9.O
            androidx.compose.runtime.V r5 = androidx.compose.runtime.C0804k.a
            if (r4 == 0) goto L40
            int r4 = r0.k
            int r4 = r4 + r3
            r0.k = r4
            androidx.compose.runtime.D0 r0 = r9.H
            r0.Q(r5, r1, r5, r10)
            r9.t(r1, r2)
            return
        L40:
            int r4 = r0.g()
            if (r4 != r10) goto L60
            int r4 = r0.g
            int r6 = r0.h
            if (r4 >= r6) goto L59
            int r4 = r4 * 5
            int r4 = r4 + r3
            int[] r6 = r0.b
            r4 = r6[r4]
            r6 = 536870912(0x20000000, float:1.0842022E-19)
            r4 = r4 & r6
            if (r4 == 0) goto L59
            goto L60
        L59:
            r0.s()
            r9.t(r1, r2)
            return
        L60:
            int r4 = r0.k
            if (r4 <= 0) goto L65
            goto L81
        L65:
            int r4 = r0.g
            int r6 = r0.h
            if (r4 != r6) goto L6c
            goto L81
        L6c:
            int r6 = r9.j
            r9.F()
            int r7 = r0.q()
            androidx.compose.runtime.changelist.b r8 = r9.L
            r8.g(r6, r7)
            java.util.ArrayList r6 = r9.r
            int r7 = r0.g
            androidx.compose.runtime.r.a(r6, r4, r7)
        L81:
            int r4 = r0.k
            int r4 = r4 + r3
            r0.k = r4
            r9.O = r3
            r9.J = r2
            androidx.compose.runtime.D0 r0 = r9.H
            boolean r0 = r0.w
            if (r0 == 0) goto L9f
            androidx.compose.runtime.A0 r0 = r9.G
            androidx.compose.runtime.D0 r0 = r0.g()
            r9.H = r0
            r0.L()
            r9.I = r1
            r9.J = r2
        L9f:
            androidx.compose.runtime.D0 r0 = r9.H
            r0.d()
            int r3 = r0.t
            r0.Q(r5, r1, r5, r10)
            androidx.compose.runtime.b r10 = r0.b(r3)
            r9.M = r10
            r9.t(r1, r2)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.C0814p.X(int):void");
    }

    public final void Y(int i) {
        R(null, i, null, 0);
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x006f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final androidx.compose.runtime.C0814p Z(int r5) {
        /*
            r4 = this;
            r4.X(r5)
            boolean r5 = r4.O
            androidx.compose.runtime.w r0 = r4.g
            java.util.ArrayList r1 = r4.D
            if (r5 == 0) goto L21
            androidx.compose.runtime.o0 r5 = new androidx.compose.runtime.o0
            r5.<init>(r0)
            r1.add(r5)
            r4.j0(r5)
            int r0 = r4.A
            r5.e = r0
            int r0 = r5.a
            r0 = r0 & (-17)
            r5.a = r0
            return r4
        L21:
            java.util.ArrayList r5 = r4.r
            androidx.compose.runtime.z0 r2 = r4.F
            int r2 = r2.i
            int r2 = androidx.compose.runtime.r.g(r2, r5)
            if (r2 < 0) goto L34
            java.lang.Object r5 = r5.remove(r2)
            androidx.compose.runtime.O r5 = (androidx.compose.runtime.O) r5
            goto L35
        L34:
            r5 = 0
        L35:
            androidx.compose.runtime.z0 r2 = r4.F
            java.lang.Object r2 = r2.k()
            androidx.compose.runtime.V r3 = androidx.compose.runtime.C0804k.a
            boolean r3 = kotlin.jvm.internal.Intrinsics.b(r2, r3)
            if (r3 == 0) goto L4c
            androidx.compose.runtime.o0 r2 = new androidx.compose.runtime.o0
            r2.<init>(r0)
            r4.j0(r2)
            goto L53
        L4c:
            java.lang.String r0 = "null cannot be cast to non-null type androidx.compose.runtime.RecomposeScopeImpl"
            kotlin.jvm.internal.Intrinsics.e(r2, r0)
            androidx.compose.runtime.o0 r2 = (androidx.compose.runtime.C0813o0) r2
        L53:
            r0 = 0
            if (r5 != 0) goto L6f
            int r5 = r2.a
            r3 = r5 & 64
            if (r3 == 0) goto L5e
            r3 = 1
            goto L5f
        L5e:
            r3 = r0
        L5f:
            if (r3 == 0) goto L65
            r5 = r5 & (-65)
            r2.a = r5
        L65:
            if (r3 == 0) goto L68
            goto L6f
        L68:
            int r5 = r2.a
            r5 = r5 & (-9)
            r2.a = r5
            goto L75
        L6f:
            int r5 = r2.a
            r5 = r5 | 8
            r2.a = r5
        L75:
            r1.add(r2)
            int r5 = r4.A
            r2.e = r5
            int r5 = r2.a
            r1 = r5 & (-17)
            r2.a = r1
            r1 = r5 & 256(0x100, float:3.59E-43)
            if (r1 == 0) goto L9d
            r5 = r5 & (-273(0xfffffffffffffeef, float:NaN))
            r5 = r5 | 512(0x200, float:7.17E-43)
            r2.a = r5
            androidx.compose.runtime.changelist.b r5 = r4.L
            androidx.compose.runtime.changelist.a r5 = r5.b
            r5.getClass()
            androidx.compose.runtime.changelist.D r1 = androidx.compose.runtime.changelist.D.c
            androidx.compose.runtime.changelist.L r5 = r5.b
            r5.f(r1)
            com.google.android.gms.internal.mlkit_vision_barcode.D4.b(r5, r0, r2)
        L9d:
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.C0814p.Z(int):androidx.compose.runtime.p");
    }

    public final void a() {
        i();
        this.h.clear();
        this.m.b = 0;
        this.s.b = 0;
        this.w.b = 0;
        this.u = null;
        C0780c c0780c = this.N;
        c0780c.c.b();
        c0780c.b.b();
        this.P = 0;
        this.z = 0;
        this.q = false;
        this.O = false;
        this.x = false;
        this.E = false;
        this.y = -1;
        C0840z0 c0840z0 = this.F;
        if (!c0840z0.f) {
            c0840z0.c();
        }
        if (this.H.w) {
            return;
        }
        u();
    }

    public final void a0(Object obj) {
        if (!this.O && this.F.g() == 207 && !Intrinsics.b(this.F.f(), obj) && this.y < 0) {
            this.y = this.F.g;
            this.x = true;
        }
        R(null, OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_SYNC_FAILED, obj, 0);
    }

    public final void b(Object obj, Function2 function2) {
        if (this.O) {
            C0780c c0780c = this.N;
            c0780c.getClass();
            androidx.compose.runtime.changelist.G g = androidx.compose.runtime.changelist.G.c;
            androidx.compose.runtime.changelist.L l = c0780c.b;
            l.f(g);
            D4.b(l, 0, obj);
            Intrinsics.e(function2, "null cannot be cast to non-null type @[ExtensionFunctionType] kotlin.Function2<kotlin.Any?, kotlin.Any?, kotlin.Unit>");
            kotlin.jvm.internal.O.d(2, function2);
            D4.b(l, 1, function2);
            return;
        }
        C0779b c0779b = this.L;
        c0779b.c();
        C0778a c0778a = c0779b.b;
        c0778a.getClass();
        androidx.compose.runtime.changelist.G g2 = androidx.compose.runtime.changelist.G.c;
        androidx.compose.runtime.changelist.L l2 = c0778a.b;
        l2.f(g2);
        Intrinsics.e(function2, "null cannot be cast to non-null type @[ExtensionFunctionType] kotlin.Function2<kotlin.Any?, kotlin.Any?, kotlin.Unit>");
        kotlin.jvm.internal.O.d(2, function2);
        D4.c(l2, 0, obj, 1, function2);
    }

    public final void b0() {
        R(null, 125, null, 2);
        this.q = true;
    }

    public final boolean c(float f) {
        Object objA = A();
        if ((objA instanceof Float) && f == ((Number) objA).floatValue()) {
            return false;
        }
        j0(Float.valueOf(f));
        return true;
    }

    public final void c0() {
        this.l = 0;
        this.F = this.c.e();
        R(null, 100, null, 0);
        AbstractC0827t abstractC0827t = this.b;
        abstractC0827t.q();
        this.t = abstractC0827t.g();
        this.w.c(this.v ? 1 : 0);
        this.v = f(this.t);
        this.J = null;
        if (!this.p) {
            this.p = abstractC0827t.e();
        }
        if (!this.B) {
            this.B = abstractC0827t.f();
        }
        Set set = (Set) C0776c.B(this.t, androidx.compose.runtime.tooling.b.a);
        if (set != null) {
            C0831v c0831v = this.Q;
            if (c0831v == null) {
                c0831v = new C0831v(this.g);
                this.Q = c0831v;
            }
            set.add(c0831v);
            abstractC0827t.n(set);
        }
        R(null, abstractC0827t.h(), null, 0);
    }

    public final boolean d(int i) {
        Object objA = A();
        if ((objA instanceof Integer) && i == ((Number) objA).intValue()) {
            return false;
        }
        j0(Integer.valueOf(i));
        return true;
    }

    public final boolean d0(C0813o0 c0813o0, Object obj) {
        C0774b c0774b = c0813o0.c;
        if (c0774b == null) {
            return false;
        }
        int iA = this.F.a.a(c0774b);
        if (!this.E || iA < this.F.g) {
            return false;
        }
        ArrayList arrayList = this.r;
        int iG = r.g(iA, arrayList);
        if (iG < 0) {
            int i = -(iG + 1);
            if (!(obj instanceof E)) {
                obj = null;
            }
            arrayList.add(i, new O(c0813o0, iA, obj));
            return true;
        }
        O o = (O) arrayList.get(iG);
        if (!(obj instanceof E)) {
            o.c = null;
            return true;
        }
        Object obj2 = o.c;
        if (obj2 == null) {
            o.c = obj;
            return true;
        }
        if (obj2 instanceof androidx.collection.J) {
            ((androidx.collection.J) obj2).a(obj);
            return true;
        }
        int i2 = androidx.collection.U.a;
        androidx.collection.J j = new androidx.collection.J(2);
        j.b[j.d(obj2)] = obj2;
        j.b[j.d(obj)] = obj;
        o.c = j;
        return true;
    }

    public final boolean e(long j) {
        Object objA = A();
        if ((objA instanceof Long) && j == ((Number) objA).longValue()) {
            return false;
        }
        j0(Long.valueOf(j));
        return true;
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x005e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void e0(androidx.collection.I r18) {
        /*
            r17 = this;
            r0 = r18
            java.lang.Object[] r1 = r0.b
            java.lang.Object[] r2 = r0.c
            long[] r0 = r0.a
            int r3 = r0.length
            int r3 = r3 + (-2)
            r4 = r17
            java.util.ArrayList r5 = r4.r
            if (r3 < 0) goto L63
            r7 = 0
        L12:
            r8 = r0[r7]
            long r10 = ~r8
            r12 = 7
            long r10 = r10 << r12
            long r10 = r10 & r8
            r12 = -9187201950435737472(0x8080808080808080, double:-2.937446524422997E-306)
            long r10 = r10 & r12
            int r10 = (r10 > r12 ? 1 : (r10 == r12 ? 0 : -1))
            if (r10 == 0) goto L5e
            int r10 = r7 - r3
            int r10 = ~r10
            int r10 = r10 >>> 31
            r11 = 8
            int r10 = 8 - r10
            r12 = 0
        L2c:
            if (r12 >= r10) goto L5c
            r13 = 255(0xff, double:1.26E-321)
            long r13 = r13 & r8
            r15 = 128(0x80, double:6.3E-322)
            int r13 = (r13 > r15 ? 1 : (r13 == r15 ? 0 : -1))
            if (r13 >= 0) goto L58
            int r13 = r7 << 3
            int r13 = r13 + r12
            r14 = r1[r13]
            r13 = r2[r13]
            java.lang.String r15 = "null cannot be cast to non-null type androidx.compose.runtime.RecomposeScopeImpl"
            kotlin.jvm.internal.Intrinsics.e(r14, r15)
            androidx.compose.runtime.o0 r14 = (androidx.compose.runtime.C0813o0) r14
            androidx.compose.runtime.b r15 = r14.c
            if (r15 == 0) goto L58
            int r15 = r15.a
            androidx.compose.runtime.V r6 = androidx.compose.runtime.V.e
            if (r13 != r6) goto L50
            r13 = 0
        L50:
            androidx.compose.runtime.O r6 = new androidx.compose.runtime.O
            r6.<init>(r14, r15, r13)
            r5.add(r6)
        L58:
            long r8 = r8 >> r11
            int r12 = r12 + 1
            goto L2c
        L5c:
            if (r10 != r11) goto L63
        L5e:
            if (r7 == r3) goto L63
            int r7 = r7 + 1
            goto L12
        L63:
            androidx.camera.camera2.internal.a0 r0 = androidx.compose.runtime.r.f
            kotlin.collections.F.t(r5, r0)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.C0814p.e0(androidx.collection.I):void");
    }

    public final boolean f(Object obj) {
        if (Intrinsics.b(A(), obj)) {
            return false;
        }
        j0(obj);
        return true;
    }

    public final void f0(int i, int i2) {
        if (k0(i) != i2) {
            if (i < 0) {
                C0221t c0221t = this.o;
                if (c0221t == null) {
                    c0221t = new C0221t();
                    this.o = c0221t;
                }
                c0221t.f(i, i2);
                return;
            }
            int[] iArr = this.n;
            if (iArr == null) {
                iArr = new int[this.F.c];
                C4930v.p(iArr, -1);
                this.n = iArr;
            }
            iArr[i] = i2;
        }
    }

    public final boolean g(boolean z) {
        Object objA = A();
        if ((objA instanceof Boolean) && z == ((Boolean) objA).booleanValue()) {
            return false;
        }
        j0(Boolean.valueOf(z));
        return true;
    }

    public final void g0(int i, int i2) {
        int iK0 = k0(i);
        if (iK0 != i2) {
            int i3 = i2 - iK0;
            ArrayList arrayList = this.h;
            int size = arrayList.size() - 1;
            while (i != -1) {
                int iK02 = k0(i) + i3;
                f0(i, iK02);
                int i4 = size;
                while (true) {
                    if (-1 < i4) {
                        C0801i0 c0801i0 = (C0801i0) arrayList.get(i4);
                        if (c0801i0 != null && c0801i0.a(i, iK02)) {
                            size = i4 - 1;
                            break;
                        }
                        i4--;
                    } else {
                        break;
                    }
                }
                if (i < 0) {
                    i = this.F.i;
                } else if (this.F.j(i)) {
                    return;
                } else {
                    i = this.F.o(i);
                }
            }
        }
    }

    public final boolean h(Object obj) {
        if (A() == obj) {
            return false;
        }
        j0(obj);
        return true;
    }

    public final androidx.compose.runtime.internal.i h0(InterfaceC0803j0 interfaceC0803j0, androidx.compose.runtime.internal.i iVar) {
        androidx.compose.runtime.internal.i iVar2 = (androidx.compose.runtime.internal.i) interfaceC0803j0;
        iVar2.getClass();
        androidx.compose.runtime.internal.h hVar = new androidx.compose.runtime.internal.h(iVar2);
        hVar.g = iVar2;
        hVar.putAll(iVar);
        androidx.compose.runtime.internal.i iVarH = hVar.build();
        T(204, r.d);
        A();
        j0(iVarH);
        A();
        j0(iVar);
        p(false);
        return iVarH;
    }

    public final void i() {
        this.i = null;
        this.j = 0;
        this.k = 0;
        this.P = 0;
        this.q = false;
        C0779b c0779b = this.L;
        c0779b.c = false;
        c0779b.d.b = 0;
        c0779b.f = 0;
        this.D.clear();
        this.n = null;
        this.o = null;
    }

    public final void i0(Object obj) {
        int i;
        C0840z0 c0840z0;
        int i2;
        D0 d0;
        if (obj instanceof InterfaceC0834w0) {
            InterfaceC0834w0 interfaceC0834w0 = (InterfaceC0834w0) obj;
            C0774b c0774bA = null;
            if (this.O) {
                D0 d02 = this.H;
                int i3 = d02.t;
                if (i3 > d02.v + 1) {
                    int i4 = i3 - 1;
                    int iE = d02.E(d02.b, i4);
                    while (true) {
                        i2 = i4;
                        i4 = iE;
                        d0 = this.H;
                        if (i4 == d0.v || i4 < 0) {
                            break;
                        } else {
                            iE = d0.E(d0.b, i4);
                        }
                    }
                    c0774bA = d0.b(i2);
                }
            } else {
                C0840z0 c0840z02 = this.F;
                int i5 = c0840z02.g;
                if (i5 > c0840z02.i + 1) {
                    int i6 = i5 - 1;
                    int iO = c0840z02.o(i6);
                    while (true) {
                        i = i6;
                        i6 = iO;
                        c0840z0 = this.F;
                        if (i6 == c0840z0.i || i6 < 0) {
                            break;
                        } else {
                            iO = c0840z0.o(i6);
                        }
                    }
                    c0774bA = c0840z0.a(i);
                }
            }
            C0836x0 c0836x0 = new C0836x0(interfaceC0834w0, c0774bA);
            if (this.O) {
                C0778a c0778a = this.L.b;
                c0778a.getClass();
                androidx.compose.runtime.changelist.x xVar = androidx.compose.runtime.changelist.x.c;
                androidx.compose.runtime.changelist.L l = c0778a.b;
                l.f(xVar);
                D4.b(l, 0, c0836x0);
            }
            this.d.add(obj);
            obj = c0836x0;
        }
        j0(obj);
    }

    public final Object j(AbstractC0809m0 abstractC0809m0) {
        return C0776c.B(l(), abstractC0809m0);
    }

    public final void j0(Object obj) {
        if (this.O) {
            this.H.S(obj);
            return;
        }
        C0840z0 c0840z0 = this.F;
        boolean z = c0840z0.n;
        C0779b c0779b = this.L;
        if (!z) {
            C0774b c0774bA = c0840z0.a(c0840z0.i);
            C0778a c0778a = c0779b.b;
            c0778a.getClass();
            C0782e c0782e = C0782e.c;
            androidx.compose.runtime.changelist.L l = c0778a.b;
            l.f(c0782e);
            D4.c(l, 0, c0774bA, 1, obj);
            return;
        }
        int iC = (c0840z0.l - C0.c(c0840z0.b, c0840z0.i)) - 1;
        if (c0779b.a.F.i - c0779b.f >= 0) {
            c0779b.e(true);
            C0778a c0778a2 = c0779b.b;
            androidx.compose.runtime.changelist.r rVar = androidx.compose.runtime.changelist.r.g;
            androidx.compose.runtime.changelist.L l2 = c0778a2.b;
            l2.f(rVar);
            D4.b(l2, 0, obj);
            l2.d[l2.e - l2.b[l2.c - 1].a] = iC;
            return;
        }
        C0840z0 c0840z02 = this.F;
        C0774b c0774bA2 = c0840z02.a(c0840z02.i);
        C0778a c0778a3 = c0779b.b;
        androidx.compose.runtime.changelist.r rVar2 = androidx.compose.runtime.changelist.r.f;
        androidx.compose.runtime.changelist.L l3 = c0778a3.b;
        l3.f(rVar2);
        D4.c(l3, 0, obj, 1, c0774bA2);
        l3.d[l3.e - l3.b[l3.c - 1].a] = iC;
    }

    public final void k(Function0 function0) {
        if (!this.q) {
            r.c("A call to createNode(), emitNode() or useNode() expected was not expected");
        }
        this.q = false;
        if (!this.O) {
            r.c("createNode() can only be called when inserting");
        }
        N n = this.m;
        int i = n.a[n.b - 1];
        D0 d0 = this.H;
        C0774b c0774bB = d0.b(d0.v);
        this.k++;
        C0780c c0780c = this.N;
        androidx.compose.runtime.changelist.r rVar = androidx.compose.runtime.changelist.r.d;
        androidx.compose.runtime.changelist.L l = c0780c.b;
        l.f(rVar);
        D4.b(l, 0, function0);
        l.d[l.e - l.b[l.c - 1].a] = i;
        D4.b(l, 1, c0774bB);
        androidx.compose.runtime.changelist.r rVar2 = androidx.compose.runtime.changelist.r.e;
        androidx.compose.runtime.changelist.L l2 = c0780c.c;
        l2.f(rVar2);
        l2.d[l2.e - l2.b[l2.c - 1].a] = i;
        D4.b(l2, 0, c0774bB);
    }

    public final int k0(int i) {
        int i2;
        if (i >= 0) {
            int[] iArr = this.n;
            return (iArr == null || (i2 = iArr[i]) < 0) ? this.F.m(i) : i2;
        }
        C0221t c0221t = this.o;
        if (c0221t == null || c0221t.c(i) < 0) {
            return 0;
        }
        int iC = c0221t.c(i);
        if (iC >= 0) {
            return c0221t.c[iC];
        }
        androidx.collection.internal.a.e("Cannot find value for key " + i);
        throw null;
    }

    public final InterfaceC0803j0 l() {
        InterfaceC0803j0 interfaceC0803j0 = this.J;
        return interfaceC0803j0 != null ? interfaceC0803j0 : m(this.F.i);
    }

    public final void l0() {
        if (!this.q) {
            r.c("A call to createNode(), emitNode() or useNode() expected was not expected");
        }
        this.q = false;
        if (this.O) {
            r.c("useNode() called while inserting");
        }
        C0840z0 c0840z0 = this.F;
        Object objL = c0840z0.l(c0840z0.i);
        C0779b c0779b = this.L;
        c0779b.d();
        c0779b.h.add(objL);
        if (this.x && (objL instanceof InterfaceC0802j)) {
            c0779b.c();
            C0778a c0778a = c0779b.b;
            c0778a.getClass();
            if (objL != null) {
                c0778a.b.f(androidx.compose.runtime.changelist.I.c);
            }
        }
    }

    public final InterfaceC0803j0 m(int i) {
        InterfaceC0803j0 interfaceC0803j0;
        boolean z = this.O;
        C0791d0 c0791d0 = r.c;
        if (z && this.I) {
            int iE = this.H.v;
            while (iE > 0) {
                D0 d0 = this.H;
                if (d0.b[d0.q(iE) * 5] == 202 && Intrinsics.b(this.H.r(iE), c0791d0)) {
                    Object objP = this.H.p(iE);
                    Intrinsics.e(objP, "null cannot be cast to non-null type androidx.compose.runtime.PersistentCompositionLocalMap");
                    InterfaceC0803j0 interfaceC0803j02 = (InterfaceC0803j0) objP;
                    this.J = interfaceC0803j02;
                    return interfaceC0803j02;
                }
                D0 d02 = this.H;
                iE = d02.E(d02.b, iE);
            }
        }
        if (this.F.c > 0) {
            while (i > 0) {
                C0840z0 c0840z0 = this.F;
                int[] iArr = c0840z0.b;
                if (iArr[i * 5] == 202 && Intrinsics.b(c0840z0.n(iArr, i), c0791d0)) {
                    C0223v c0223v = this.u;
                    if (c0223v == null || (interfaceC0803j0 = (InterfaceC0803j0) c0223v.e(i)) == null) {
                        C0840z0 c0840z02 = this.F;
                        Object objB = c0840z02.b(c0840z02.b, i);
                        Intrinsics.e(objB, "null cannot be cast to non-null type androidx.compose.runtime.PersistentCompositionLocalMap");
                        interfaceC0803j0 = (InterfaceC0803j0) objB;
                    }
                    this.J = interfaceC0803j0;
                    return interfaceC0803j0;
                }
                i = this.F.o(i);
            }
        }
        InterfaceC0803j0 interfaceC0803j03 = this.t;
        this.J = interfaceC0803j03;
        return interfaceC0803j03;
    }

    public final void n(androidx.collection.I i, androidx.compose.runtime.internal.d dVar) {
        ArrayList arrayList = this.r;
        if (this.E) {
            r.c("Reentrant composition is not supported");
        }
        Trace.beginSection("Compose:recompose");
        try {
            this.A = Long.hashCode(androidx.compose.runtime.snapshots.m.k().g());
            this.u = null;
            e0(i);
            this.j = 0;
            this.E = true;
            try {
                c0();
                Object objA = A();
                if (objA != dVar && dVar != null) {
                    j0(dVar);
                }
                C0812o c0812o = this.C;
                androidx.compose.runtime.collection.b bVarO = C0776c.o();
                try {
                    bVarO.b(c0812o);
                    C0791d0 c0791d0 = r.a;
                    if (dVar != null) {
                        T(200, c0791d0);
                        androidx.compose.runtime.internal.e.d(this, dVar);
                        p(false);
                    } else if (!this.v || objA == null || objA.equals(C0804k.a)) {
                        O();
                    } else {
                        T(200, c0791d0);
                        kotlin.jvm.internal.O.d(2, objA);
                        androidx.compose.runtime.internal.e.d(this, (Function2) objA);
                        p(false);
                    }
                    bVarO.o(bVarO.c - 1);
                    s();
                    this.E = false;
                    arrayList.clear();
                    if (!this.H.w) {
                        r.c("Check failed");
                    }
                    u();
                    Unit unit = Unit.a;
                } catch (Throwable th) {
                    bVarO.o(bVarO.c - 1);
                    throw th;
                }
            } catch (Throwable th2) {
                this.E = false;
                arrayList.clear();
                a();
                if (!this.H.w) {
                    r.c("Check failed");
                }
                u();
                throw th2;
            }
        } finally {
            Trace.endSection();
        }
    }

    public final void o(int i, int i2) {
        if (i <= 0 || i == i2) {
            return;
        }
        o(this.F.o(i), i2);
        if (this.F.j(i)) {
            Object objL = this.F.l(i);
            C0779b c0779b = this.L;
            c0779b.d();
            c0779b.h.add(objL);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:148:0x0396  */
    /* JADX WARN: Type inference failed for: r6v3 */
    /* JADX WARN: Type inference failed for: r6v4, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r6v8 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void p(boolean r42) {
        /*
            Method dump skipped, instructions count: 1396
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.C0814p.p(boolean):void");
    }

    public final void q() {
        p(false);
        C0813o0 c0813o0V = v();
        if (c0813o0V != null) {
            int i = c0813o0V.a;
            if ((i & 1) != 0) {
                c0813o0V.a = i | 2;
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:26:0x0077  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x007c A[EDGE_INSN: B:57:0x007c->B:28:0x007c BREAK  A[LOOP:0: B:15:0x0037->B:27:0x0079], EDGE_INSN: B:58:0x007c->B:28:0x007c BREAK  A[LOOP:0: B:15:0x0037->B:27:0x0079]] */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0081  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0099  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x00e2  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final androidx.compose.runtime.C0813o0 r() {
        /*
            Method dump skipped, instructions count: 232
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.C0814p.r():androidx.compose.runtime.o0");
    }

    public final void s() {
        p(false);
        this.b.c();
        p(false);
        C0779b c0779b = this.L;
        if (c0779b.c) {
            c0779b.e(false);
            c0779b.e(false);
            C0778a c0778a = c0779b.b;
            c0778a.getClass();
            c0778a.b.f(androidx.compose.runtime.changelist.m.c);
            c0779b.c = false;
        }
        c0779b.c();
        if (c0779b.d.b != 0) {
            r.c("Missed recording an endGroup()");
        }
        if (!this.h.isEmpty()) {
            r.c("Start/end imbalance");
        }
        i();
        this.F.c();
        this.v = this.w.b() != 0;
    }

    public final void t(boolean z, C0801i0 c0801i0) {
        this.h.add(this.i);
        this.i = c0801i0;
        int i = this.k;
        N n = this.m;
        n.c(i);
        n.c(this.l);
        n.c(this.j);
        if (z) {
            this.j = 0;
        }
        this.k = 0;
        this.l = 0;
    }

    public final void u() {
        A0 a0 = new A0();
        if (this.B) {
            a0.b();
        }
        if (this.b.d()) {
            a0.k = new C0223v();
        }
        this.G = a0;
        D0 d0G = a0.g();
        d0G.e(true);
        this.H = d0G;
    }

    public final C0813o0 v() {
        if (this.z != 0) {
            return null;
        }
        ArrayList arrayList = this.D;
        if (arrayList.isEmpty()) {
            return null;
        }
        return (C0813o0) android.support.v4.media.session.a.e(1, arrayList);
    }

    public final boolean w() {
        if (!x() || this.v) {
            return true;
        }
        C0813o0 c0813o0V = v();
        return (c0813o0V == null || (c0813o0V.a & 4) == 0) ? false : true;
    }

    public final boolean x() {
        C0813o0 c0813o0V;
        return (this.O || this.x || this.v || (c0813o0V = v()) == null || (c0813o0V.a & 8) != 0) ? false : true;
    }

    /* JADX WARN: Can't wrap try/catch for region: R(13:(14:(42:45|(1:47)|48|(1:50)(1:51)|52|(1:54)(1:55)|(0)|60|161|61|62|(4:64|(4:66|67|146|68)(1:69)|70|(1:72))(1:75)|76|151|77|140|78|159|79|80|153|81|82|149|83|84|144|85|86|173|87|88|167|89|157|90|171|91|(1:93)|147|94|95)(1:58)|173|87|88|167|89|157|90|171|91|(0)|147|94|95)|159|79|80|153|81|82|149|83|84|144|85|86) */
    /* JADX WARN: Code restructure failed: missing block: B:103:0x0205, code lost:
    
        r0 = th;
     */
    /* JADX WARN: Code restructure failed: missing block: B:104:0x0206, code lost:
    
        r8 = r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:105:0x0207, code lost:
    
        r23 = r7;
     */
    /* JADX WARN: Code restructure failed: missing block: B:106:0x020a, code lost:
    
        r0 = th;
     */
    /* JADX WARN: Code restructure failed: missing block: B:107:0x020b, code lost:
    
        r8 = r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:108:0x020d, code lost:
    
        r0 = th;
     */
    /* JADX WARN: Code restructure failed: missing block: B:109:0x020e, code lost:
    
        r8 = r3;
        r23 = r7;
        r7 = r2;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:64:0x0133 A[Catch: all -> 0x0233, TryCatch #8 {all -> 0x0233, blocks: (B:7:0x001e, B:9:0x0031, B:39:0x00c9, B:60:0x0118, B:62:0x012a, B:64:0x0133, B:66:0x013e, B:59:0x0116, B:43:0x00d2), top: B:155:0x001e }] */
    /* JADX WARN: Removed duplicated region for block: B:75:0x016b  */
    /* JADX WARN: Removed duplicated region for block: B:93:0x01d0 A[Catch: all -> 0x021e, TRY_LEAVE, TryCatch #16 {all -> 0x021e, blocks: (B:91:0x01c3, B:93:0x01d0, B:116:0x021b, B:117:0x021d), top: B:171:0x01c3 }] */
    /* JADX WARN: Type inference failed for: r0v29, types: [java.lang.Object, java.util.List] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void y(java.util.ArrayList r25) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 600
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.C0814p.y(java.util.ArrayList):void");
    }

    public final void z(X x, InterfaceC0803j0 interfaceC0803j0, Object obj, boolean z) {
        U(126665345, x);
        A();
        j0(obj);
        int i = this.P;
        try {
            this.P = 126665345;
            if (this.O) {
                D0.x(this.H);
            }
            boolean z2 = (this.O || Intrinsics.b(this.F.f(), interfaceC0803j0)) ? false : true;
            if (z2) {
                G(interfaceC0803j0);
            }
            R(r.c, 202, interfaceC0803j0, 0);
            this.J = null;
            if (!this.O || z) {
                boolean z3 = this.v;
                this.v = z2;
                androidx.compose.runtime.internal.e.d(this, new androidx.compose.runtime.internal.d(true, 316014703, new androidx.compose.foundation.contextmenu.i(22, x, obj)));
                this.v = z3;
            } else {
                this.I = true;
                D0 d0 = this.H;
                this.b.j(new Z(x, obj, this.g, this.G, d0.b(d0.E(d0.b, d0.v)), kotlin.collections.K.a, l(), null));
            }
            p(false);
            this.J = null;
            this.P = i;
            p(false);
        } catch (Throwable th) {
            p(false);
            this.J = null;
            this.P = i;
            p(false);
            throw th;
        }
    }
}

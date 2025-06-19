package androidx.compose.foundation.text.selection;

import androidx.collection.AbstractC0216n;
import androidx.collection.AbstractC0217o;
import androidx.collection.C0225x;
import androidx.compose.animation.C0281h;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import androidx.compose.ui.platform.InterfaceC0949j0;
import androidx.compose.ui.platform.S0;
import androidx.compose.ui.text.C0995g;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class U {
    public final b0 a;
    public androidx.compose.ui.hapticfeedback.a e;
    public InterfaceC0949j0 f;
    public S0 g;
    public androidx.compose.ui.geometry.b j;
    public androidx.compose.ui.layout.r k;
    public I r;
    public boolean s;
    public final InterfaceC0773a0 b = C0776c.z(null);
    public final InterfaceC0773a0 c = C0776c.z(Boolean.TRUE);
    public kotlin.jvm.internal.r d = new C0541w(this, 8);
    public final androidx.compose.ui.focus.p h = new androidx.compose.ui.focus.p();
    public final InterfaceC0773a0 i = C0776c.z(Boolean.FALSE);
    public final InterfaceC0773a0 l = C0776c.z(new androidx.compose.ui.geometry.b(0));
    public final InterfaceC0773a0 m = C0776c.z(new androidx.compose.ui.geometry.b(0));
    public final InterfaceC0773a0 n = C0776c.z(null);
    public final InterfaceC0773a0 o = C0776c.z(null);
    public final InterfaceC0773a0 p = C0776c.z(null);
    public final InterfaceC0773a0 q = C0776c.z(null);

    public U(b0 b0Var) {
        this.a = b0Var;
        b0Var.e = new C0541w(this, 1);
        b0Var.f = new androidx.compose.foundation.lazy.f(this, 1);
        new C0281h(this, 12);
        b0Var.g = new P(this);
        b0Var.h = new C0540v(this, 2);
        b0Var.i = new C0541w(this, 2);
        b0Var.j = new C0541w(this, 3);
    }

    public static final long a(U u, androidx.compose.ui.layout.r rVar, long j) {
        androidx.compose.ui.layout.r rVar2 = u.k;
        if (rVar2 == null || !rVar2.k()) {
            return 9205357640488583168L;
        }
        return u.j().f(rVar, j);
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x0062  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b() {
        /*
            r10 = this;
            androidx.compose.foundation.text.selection.q r0 = r10.e()
            r1 = 0
            if (r0 == 0) goto L62
            androidx.compose.foundation.text.selection.b0 r0 = r10.a
            androidx.collection.z r2 = r0.a()
            int r2 = r2.e
            if (r2 != 0) goto L12
            goto L62
        L12:
            androidx.compose.ui.text.d r2 = new androidx.compose.ui.text.d
            r2.<init>()
            androidx.compose.ui.layout.r r3 = r10.j()
            java.util.ArrayList r3 = r0.c(r3)
            int r4 = r3.size()
            r5 = 0
        L24:
            if (r5 >= r4) goto L5d
            java.lang.Object r6 = r3.get(r5)
            androidx.compose.foundation.text.selection.m r6 = (androidx.compose.foundation.text.selection.C0532m) r6
            androidx.collection.z r7 = r0.a()
            long r8 = r6.a
            java.lang.Object r7 = r7.d(r8)
            androidx.compose.foundation.text.selection.q r7 = (androidx.compose.foundation.text.selection.C0536q) r7
            if (r7 == 0) goto L5a
            androidx.compose.ui.text.g r6 = r6.e()
            boolean r8 = r7.c
            androidx.compose.foundation.text.selection.p r9 = r7.a
            androidx.compose.foundation.text.selection.p r7 = r7.b
            if (r8 == 0) goto L4f
            int r7 = r7.b
            int r8 = r9.b
            androidx.compose.ui.text.g r6 = r6.subSequence(r7, r8)
            goto L57
        L4f:
            int r8 = r9.b
            int r7 = r7.b
            androidx.compose.ui.text.g r6 = r6.subSequence(r8, r7)
        L57:
            r2.d(r6)
        L5a:
            int r5 = r5 + 1
            goto L24
        L5d:
            androidx.compose.ui.text.g r0 = r2.j()
            goto L63
        L62:
            r0 = r1
        L63:
            if (r0 == 0) goto L79
            java.lang.String r2 = r0.a
            int r2 = r2.length()
            if (r2 <= 0) goto L6e
            r1 = r0
        L6e:
            if (r1 == 0) goto L79
            androidx.compose.ui.platform.j0 r0 = r10.f
            if (r0 == 0) goto L79
            androidx.compose.ui.platform.g r0 = (androidx.compose.ui.platform.C0942g) r0
            r0.a(r1)
        L79:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.selection.U.b():void");
    }

    public final androidx.compose.foundation.text.U c() {
        return (androidx.compose.foundation.text.U) ((L0) this.p).getValue();
    }

    public final boolean d() {
        return ((Boolean) ((L0) this.i).getValue()).booleanValue();
    }

    public final C0536q e() {
        return (C0536q) ((L0) this.b).getValue();
    }

    public final boolean f() {
        C0536q c0536q;
        androidx.compose.ui.layout.r rVarJ = j();
        b0 b0Var = this.a;
        ArrayList arrayListC = b0Var.c(rVarJ);
        if (arrayListC.isEmpty()) {
            return true;
        }
        int size = arrayListC.size();
        for (int i = 0; i < size; i++) {
            C0532m c0532m = (C0532m) arrayListC.get(i);
            C0995g c0995gE = c0532m.e();
            if (c0995gE.a.length() != 0 && ((c0536q = (C0536q) b0Var.a().d(c0532m.a)) == null || Math.abs(c0536q.a.b - c0536q.b.b) != c0995gE.a.length())) {
                return false;
            }
        }
        return true;
    }

    public final boolean g() {
        return ((Boolean) ((L0) this.c).getValue()).booleanValue();
    }

    public final boolean h() {
        C0536q c0536qE = e();
        if (c0536qE != null) {
            C0535p c0535p = c0536qE.a;
            C0535p c0535p2 = c0536qE.b;
            if (!Intrinsics.b(c0535p, c0535p2)) {
                if (c0535p.c == c0535p2.c) {
                    return true;
                }
                androidx.compose.ui.layout.r rVarJ = j();
                b0 b0Var = this.a;
                ArrayList arrayListC = b0Var.c(rVarJ);
                int size = arrayListC.size();
                for (int i = 0; i < size; i++) {
                    C0536q c0536q = (C0536q) b0Var.a().d(((C0532m) arrayListC.get(i)).a);
                    if (c0536q != null && c0536q.a.b != c0536q.b.b) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /* JADX WARN: Type inference failed for: r0v3, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    public final void i() {
        androidx.compose.ui.hapticfeedback.a aVar;
        androidx.collection.z zVar = AbstractC0217o.a;
        Intrinsics.e(zVar, "null cannot be cast to non-null type androidx.collection.LongObjectMap<V of androidx.collection.LongObjectMapKt.emptyLongObjectMap>");
        ((L0) this.a.k).setValue(zVar);
        n(false);
        if (e() != null) {
            this.d.invoke(null);
            if (!g() || (aVar = this.e) == null) {
                return;
            }
            ((androidx.compose.ui.hapticfeedback.b) aVar).a();
        }
    }

    public final androidx.compose.ui.layout.r j() {
        androidx.compose.ui.layout.r rVar = this.k;
        if (rVar == null) {
            throw new IllegalArgumentException("null coordinates");
        }
        if (rVar.k()) {
            return rVar;
        }
        throw new IllegalArgumentException("unattached coordinates");
    }

    /* JADX WARN: Type inference failed for: r0v5, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    public final void k() {
        androidx.compose.ui.layout.r rVarJ = j();
        b0 b0Var = this.a;
        ArrayList arrayListC = b0Var.c(rVarJ);
        if (arrayListC.isEmpty()) {
            return;
        }
        androidx.collection.z zVar = AbstractC0217o.a;
        androidx.collection.z zVar2 = new androidx.collection.z();
        int size = arrayListC.size();
        C0536q c0536q = null;
        C0536q c0536q2 = null;
        for (int i = 0; i < size; i++) {
            C0532m c0532m = (C0532m) arrayListC.get(i);
            C0536q c0536qD = c0532m.d();
            if (c0536qD != null) {
                if (c0536q == null) {
                    c0536q = c0536qD;
                }
                long j = c0532m.a;
                int iB = zVar2.b(j);
                Object[] objArr = zVar2.c;
                Object obj = objArr[iB];
                zVar2.b[iB] = j;
                objArr[iB] = c0536qD;
                c0536q2 = c0536qD;
            }
        }
        if (zVar2.e == 0) {
            return;
        }
        if (c0536q != c0536q2) {
            Intrinsics.d(c0536q);
            Intrinsics.d(c0536q2);
            c0536q = new C0536q(c0536q.a, c0536q2.b, false);
        }
        ((L0) b0Var.k).setValue(zVar2);
        this.d.invoke(c0536q);
        this.r = null;
    }

    public final void l(boolean z) {
        InterfaceC0773a0 interfaceC0773a0 = this.c;
        if (((Boolean) ((L0) interfaceC0773a0).getValue()).booleanValue() != z) {
            ((L0) interfaceC0773a0).setValue(Boolean.valueOf(z));
            q();
        }
    }

    public final void m(C0536q c0536q) {
        ((L0) this.b).setValue(c0536q);
        if (c0536q != null) {
            o();
        }
    }

    public final void n(boolean z) {
        this.s = z;
        q();
    }

    /* JADX WARN: Removed duplicated region for block: B:37:0x007a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void o() {
        /*
            r13 = this;
            androidx.compose.foundation.text.selection.q r0 = r13.e()
            androidx.compose.ui.layout.r r1 = r13.k
            androidx.compose.foundation.text.selection.b0 r2 = r13.a
            r3 = 0
            if (r0 == 0) goto L1a
            androidx.compose.foundation.text.selection.p r4 = r0.a
            if (r4 == 0) goto L1a
            androidx.collection.z r5 = r2.c
            long r6 = r4.c
            java.lang.Object r4 = r5.d(r6)
            androidx.compose.foundation.text.selection.m r4 = (androidx.compose.foundation.text.selection.C0532m) r4
            goto L1b
        L1a:
            r4 = r3
        L1b:
            if (r0 == 0) goto L2c
            androidx.compose.foundation.text.selection.p r5 = r0.b
            if (r5 == 0) goto L2c
            androidx.collection.z r2 = r2.c
            long r5 = r5.c
            java.lang.Object r2 = r2.d(r5)
            androidx.compose.foundation.text.selection.m r2 = (androidx.compose.foundation.text.selection.C0532m) r2
            goto L2d
        L2c:
            r2 = r3
        L2d:
            if (r4 == 0) goto L34
            androidx.compose.ui.layout.r r5 = r4.c()
            goto L35
        L34:
            r5 = r3
        L35:
            if (r2 == 0) goto L3c
            androidx.compose.ui.layout.r r6 = r2.c()
            goto L3d
        L3c:
            r6 = r3
        L3d:
            androidx.compose.runtime.a0 r7 = r13.o
            androidx.compose.runtime.a0 r8 = r13.n
            if (r0 == 0) goto Lac
            if (r1 == 0) goto Lac
            boolean r9 = r1.k()
            if (r9 == 0) goto Lac
            if (r5 != 0) goto L50
            if (r6 != 0) goto L50
            goto Lac
        L50:
            androidx.compose.ui.geometry.c r9 = androidx.compose.foundation.text.selection.W.y(r1)
            if (r5 == 0) goto L7a
            r10 = 1
            long r10 = r4.a(r0, r10)
            boolean r4 = com.google.android.gms.internal.mlkit_vision_barcode.Q4.i(r10)
            if (r4 == 0) goto L62
            goto L7a
        L62:
            long r4 = r1.f(r5, r10)
            androidx.compose.ui.geometry.b r10 = new androidx.compose.ui.geometry.b
            r10.<init>(r4)
            androidx.compose.foundation.text.U r11 = r13.c()
            androidx.compose.foundation.text.U r12 = androidx.compose.foundation.text.U.b
            if (r11 == r12) goto L7b
            boolean r4 = androidx.compose.foundation.text.selection.W.p(r9, r4)
            if (r4 == 0) goto L7a
            goto L7b
        L7a:
            r10 = r3
        L7b:
            androidx.compose.runtime.L0 r8 = (androidx.compose.runtime.L0) r8
            r8.setValue(r10)
            if (r6 == 0) goto La6
            r4 = 0
            long r4 = r2.a(r0, r4)
            boolean r0 = com.google.android.gms.internal.mlkit_vision_barcode.Q4.i(r4)
            if (r0 == 0) goto L8e
            goto La6
        L8e:
            long r0 = r1.f(r6, r4)
            androidx.compose.ui.geometry.b r2 = new androidx.compose.ui.geometry.b
            r2.<init>(r0)
            androidx.compose.foundation.text.U r4 = r13.c()
            androidx.compose.foundation.text.U r5 = androidx.compose.foundation.text.U.c
            if (r4 == r5) goto La5
            boolean r0 = androidx.compose.foundation.text.selection.W.p(r9, r0)
            if (r0 == 0) goto La6
        La5:
            r3 = r2
        La6:
            androidx.compose.runtime.L0 r7 = (androidx.compose.runtime.L0) r7
            r7.setValue(r3)
            return
        Lac:
            androidx.compose.runtime.L0 r8 = (androidx.compose.runtime.L0) r8
            r8.setValue(r3)
            androidx.compose.runtime.L0 r7 = (androidx.compose.runtime.L0) r7
            r7.setValue(r3)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.selection.U.o():void");
    }

    /* JADX WARN: Type inference failed for: r2v15, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    public final boolean p(long j, long j2, boolean z, r rVar) {
        ArrayList arrayList;
        I f0Var;
        androidx.compose.ui.text.H h;
        b0 b0Var;
        int i;
        int i2;
        J j3;
        int i3;
        long j4;
        int i4;
        int iN;
        int i5;
        int i6;
        int i7;
        int i8;
        int i9;
        J j5;
        int i10;
        int iS;
        C0535p c0535p;
        C0535p c0535p2;
        C0535p c0535p3;
        int i11 = 1;
        ((L0) this.p).setValue(z ? androidx.compose.foundation.text.U.b : androidx.compose.foundation.text.U.c);
        ((L0) this.q).setValue(new androidx.compose.ui.geometry.b(j));
        androidx.compose.ui.layout.r rVarJ = j();
        b0 b0Var2 = this.a;
        ArrayList arrayListC = b0Var2.c(rVarJ);
        int i12 = AbstractC0216n.a;
        C0225x c0225x = new C0225x(6);
        int size = arrayListC.size();
        for (int i13 = 0; i13 < size; i13++) {
            c0225x.e(i13, ((C0532m) arrayListC.get(i13)).a);
        }
        J j6 = new J(j, j2, rVarJ, z, Q4.i(j2) ? null : e(), new androidx.camera.core.streamsharing.a(c0225x, i11));
        int size2 = arrayListC.size();
        int i14 = 0;
        while (true) {
            arrayList = j6.h;
            if (i14 >= size2) {
                break;
            }
            C0532m c0532m = (C0532m) arrayListC.get(i14);
            androidx.compose.ui.layout.r rVarC = c0532m.c();
            if (rVarC == null || (h = (androidx.compose.ui.text.H) c0532m.c.invoke()) == null) {
                i = i11;
                b0Var = b0Var2;
                j5 = j6;
                i2 = size2;
            } else {
                long jF = j6.c.f(rVarC, 0L);
                int i15 = i11;
                b0Var = b0Var2;
                long jG = androidx.compose.ui.geometry.b.g(j6.a, jF);
                long j7 = j6.b;
                long jG2 = Q4.i(j7) ? 9205357640488583168L : androidx.compose.ui.geometry.b.g(j7, jF);
                long j8 = h.c;
                i = i15;
                float f = (int) (j8 & 4294967295L);
                int i16 = 3;
                int i17 = androidx.compose.ui.geometry.b.d(jG) < DefinitionKt.NO_Float_VALUE ? i : androidx.compose.ui.geometry.b.d(jG) > ((float) ((int) (j8 >> 32))) ? 3 : 2;
                if (androidx.compose.ui.geometry.b.e(jG) < DefinitionKt.NO_Float_VALUE) {
                    i16 = i;
                } else if (androidx.compose.ui.geometry.b.e(jG) <= f) {
                    i16 = 2;
                }
                boolean z2 = j6.d;
                long j9 = c0532m.a;
                i2 = size2;
                C0536q c0536q = j6.e;
                if (z2) {
                    if (c0536q != null) {
                        c0535p3 = c0536q.b;
                        j3 = j6;
                        j4 = j9;
                        i4 = 2;
                        i3 = i17;
                    } else {
                        c0535p3 = null;
                        j3 = j6;
                        i3 = i17;
                        j4 = j9;
                        i4 = 2;
                    }
                    iN = W.n(i3, i16, j3, j4, c0535p3);
                    i9 = iN;
                    i8 = i9;
                    i6 = i3;
                    i5 = i16;
                    i7 = i5;
                } else {
                    j3 = j6;
                    i3 = i17;
                    j4 = j9;
                    i4 = 2;
                    iN = W.n(i3, i16, j3, j4, c0536q != null ? c0536q.a : null);
                    i5 = i16;
                    i6 = iN;
                    i7 = i6;
                    i8 = i5;
                    i9 = i3;
                }
                j5 = j3;
                int iX = W.x(i3, i5);
                if (iX == i4 || iX != iN) {
                    int length = h.a.a.a.length();
                    androidx.camera.core.streamsharing.a aVar = j5.f;
                    if (z2) {
                        iS = W.s(jG, h);
                        if (c0536q == null || (c0535p2 = c0536q.b) == null) {
                            length = iS;
                        } else {
                            int iCompare = aVar.compare(Long.valueOf(c0535p2.c), Long.valueOf(j4));
                            if (iCompare < 0) {
                                length = 0;
                            } else if (iCompare <= 0) {
                                length = c0535p2.b;
                            }
                        }
                        i10 = length;
                    } else {
                        int iS2 = W.s(jG, h);
                        if (c0536q == null || (c0535p = c0536q.a) == null) {
                            length = iS2;
                        } else {
                            int iCompare2 = aVar.compare(Long.valueOf(c0535p.c), Long.valueOf(j4));
                            if (iCompare2 < 0) {
                                length = 0;
                            } else if (iCompare2 <= 0) {
                                length = c0535p.b;
                            }
                        }
                        i10 = iS2;
                        iS = length;
                    }
                    int iS3 = Q4.i(jG2) ? -1 : W.s(jG2, h);
                    int i18 = j5.k + 2;
                    j5.k = i18;
                    long j10 = j4;
                    C0534o c0534o = new C0534o(j10, i18, iS, i10, iS3, h);
                    j5.i = j5.a(j5.i, i6, i7);
                    j5.j = j5.a(j5.j, i9, i8);
                    j5.g.e(arrayList.size(), j10);
                    arrayList.add(c0534o);
                }
            }
            i14++;
            size2 = i2;
            i11 = i;
            b0Var2 = b0Var;
            j6 = j5;
        }
        int i19 = i11;
        b0 b0Var3 = b0Var2;
        J j11 = j6;
        int i20 = j11.k + 1;
        int size3 = arrayList.size();
        if (size3 == 0) {
            throw new IllegalStateException("SelectionLayout must not be empty.");
        }
        if (size3 != i19) {
            int i21 = j11.i;
            int i22 = i21 == -1 ? i20 : i21;
            int i23 = j11.j;
            f0Var = new C0531l(j11.g, arrayList, i22, i23 == -1 ? i20 : i23, j11.d, j11.e);
        } else {
            C0534o c0534o2 = (C0534o) CollectionsKt.j0(arrayList);
            int i24 = j11.i;
            int i25 = i24 == -1 ? i20 : i24;
            int i26 = j11.j;
            f0Var = new f0(j11.d, i25, i26 == -1 ? i20 : i26, j11.e, c0534o2);
        }
        if (!f0Var.g(this.r)) {
            return false;
        }
        C0536q c0536qA = rVar.a(f0Var);
        if (!Intrinsics.b(c0536qA, e())) {
            if (g()) {
                ArrayList arrayList2 = b0Var3.b;
                int size4 = arrayList2.size();
                int i27 = 0;
                while (true) {
                    if (i27 >= size4) {
                        break;
                    }
                    if (((C0532m) arrayList2.get(i27)).e().a.length() > 0) {
                        androidx.compose.ui.hapticfeedback.a aVar2 = this.e;
                        if (aVar2 != null) {
                            ((androidx.compose.ui.hapticfeedback.b) aVar2).a();
                        }
                    } else {
                        i27++;
                    }
                }
            }
            ((L0) b0Var3.k).setValue(f0Var.f(c0536qA));
            this.d.invoke(c0536qA);
        }
        this.r = f0Var;
        return true;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:14:0x0021  */
    /* JADX WARN: Type inference failed for: r6v7, types: [java.util.List] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void q() {
        /*
            Method dump skipped, instructions count: 574
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.selection.U.q():void");
    }
}

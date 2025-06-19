package androidx.compose.foundation.lazy.layout;

import androidx.compose.animation.core.C0253l0;
import androidx.compose.runtime.L0;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class K {
    public final androidx.collection.I a;
    public P b;
    public int c;
    public final androidx.collection.J d;
    public final ArrayList e;
    public final ArrayList f;
    public final ArrayList g;
    public final ArrayList h;
    public final ArrayList i;
    public G j;
    public final androidx.compose.ui.q k;

    public K() {
        long[] jArr = androidx.collection.S.a;
        this.a = new androidx.collection.I();
        int i = androidx.collection.U.a;
        this.d = new androidx.collection.J();
        this.e = new ArrayList();
        this.f = new ArrayList();
        this.g = new ArrayList();
        this.h = new ArrayList();
        this.i = new ArrayList();
        this.k = new androidx.compose.ui.node.T(this) { // from class: androidx.compose.foundation.lazy.layout.LazyLayoutItemAnimator$DisplayingDisappearingItemsElement
            public final K b;

            {
                this.b = this;
            }

            public final boolean equals(Object obj) {
                if (this == obj) {
                    return true;
                }
                return (obj instanceof LazyLayoutItemAnimator$DisplayingDisappearingItemsElement) && Intrinsics.b(this.b, ((LazyLayoutItemAnimator$DisplayingDisappearingItemsElement) obj).b);
            }

            public final int hashCode() {
                return this.b.hashCode();
            }

            @Override // androidx.compose.ui.node.T
            public final androidx.compose.ui.p l() {
                G g = new G();
                g.n = this.b;
                return g;
            }

            @Override // androidx.compose.ui.node.T
            public final void n(androidx.compose.ui.p pVar) {
                G g = (G) pVar;
                K k = g.n;
                K k2 = this.b;
                if (Intrinsics.b(k, k2) || !g.a.m) {
                    return;
                }
                g.n.f();
                k2.j = g;
                g.n = k2;
            }

            public final String toString() {
                return "DisplayingDisappearingItemsElement(animator=" + this.b + ')';
            }
        };
    }

    public static void c(V v, int i, H h) {
        int i2 = 0;
        long jI = v.i(0);
        long jA = v.g() ? androidx.compose.ui.unit.h.a(jI, 0, i, 1) : androidx.compose.ui.unit.h.a(jI, i, 0, 2);
        E[] eArr = h.a;
        int length = eArr.length;
        int i3 = 0;
        while (i2 < length) {
            E e = eArr[i2];
            int i4 = i3 + 1;
            if (e != null) {
                e.l = androidx.compose.ui.unit.h.d(jA, androidx.compose.ui.unit.h.c(v.i(i3), jI));
            }
            i2++;
            i3 = i4;
        }
    }

    public static int h(int[] iArr, V v) {
        int iJ = v.j();
        int iD = v.d() + iJ;
        int iMax = 0;
        while (iJ < iD) {
            int iC = v.c() + iArr[iJ];
            iArr[iJ] = iC;
            iMax = Math.max(iMax, iC);
            iJ++;
        }
        return iMax;
    }

    public final E a(int i, Object obj) {
        E[] eArr;
        H h = (H) this.a.f(obj);
        if (h == null || (eArr = h.a) == null) {
            return null;
        }
        return eArr[i];
    }

    public final long b() {
        ArrayList arrayList = this.i;
        int size = arrayList.size();
        long jA = 0;
        for (int i = 0; i < size; i++) {
            E e = (E) arrayList.get(i);
            androidx.compose.ui.graphics.layer.b bVar = e.n;
            if (bVar != null) {
                jA = R5.a(Math.max((int) (jA >> 32), ((int) (e.l >> 32)) + ((int) (bVar.t >> 32))), Math.max((int) (jA & 4294967295L), ((int) (e.l & 4294967295L)) + ((int) (bVar.t & 4294967295L))));
            }
        }
        return jA;
    }

    /* JADX WARN: Removed duplicated region for block: B:177:0x03c2  */
    /* JADX WARN: Removed duplicated region for block: B:181:0x03d1  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x00c4  */
    /* JADX WARN: Type inference failed for: r13v16, types: [kotlin.coroutines.CoroutineContext, kotlin.coroutines.h, kotlinx.coroutines.D] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void d(int r48, int r49, int r50, java.util.ArrayList r51, androidx.appcompat.widget.C0122z r52, androidx.compose.foundation.lazy.layout.W r53, boolean r54, boolean r55, int r56, boolean r57, int r58, int r59, kotlinx.coroutines.C r60, androidx.compose.ui.graphics.E r61) {
        /*
            Method dump skipped, instructions count: 1489
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.lazy.layout.K.d(int, int, int, java.util.ArrayList, androidx.appcompat.widget.z, androidx.compose.foundation.lazy.layout.W, boolean, boolean, int, boolean, int, int, kotlinx.coroutines.C, androidx.compose.ui.graphics.E):void");
    }

    public final void e(Object obj) {
        E[] eArr;
        H h = (H) this.a.h(obj);
        if (h == null || (eArr = h.a) == null) {
            return;
        }
        for (E e : eArr) {
            if (e != null) {
                e.c();
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x0053  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void f() {
        /*
            r15 = this;
            androidx.collection.I r0 = r15.a
            int r1 = r0.e
            if (r1 == 0) goto L5b
            java.lang.Object[] r1 = r0.c
            long[] r2 = r0.a
            int r3 = r2.length
            int r3 = r3 + (-2)
            if (r3 < 0) goto L58
            r4 = 0
            r5 = r4
        L11:
            r6 = r2[r5]
            long r8 = ~r6
            r10 = 7
            long r8 = r8 << r10
            long r8 = r8 & r6
            r10 = -9187201950435737472(0x8080808080808080, double:-2.937446524422997E-306)
            long r8 = r8 & r10
            int r8 = (r8 > r10 ? 1 : (r8 == r10 ? 0 : -1))
            if (r8 == 0) goto L53
            int r8 = r5 - r3
            int r8 = ~r8
            int r8 = r8 >>> 31
            r9 = 8
            int r8 = 8 - r8
            r10 = r4
        L2b:
            if (r10 >= r8) goto L51
            r11 = 255(0xff, double:1.26E-321)
            long r11 = r11 & r6
            r13 = 128(0x80, double:6.3E-322)
            int r11 = (r11 > r13 ? 1 : (r11 == r13 ? 0 : -1))
            if (r11 >= 0) goto L4d
            int r11 = r5 << 3
            int r11 = r11 + r10
            r11 = r1[r11]
            androidx.compose.foundation.lazy.layout.H r11 = (androidx.compose.foundation.lazy.layout.H) r11
            androidx.compose.foundation.lazy.layout.E[] r11 = r11.a
            int r12 = r11.length
            r13 = r4
        L41:
            if (r13 >= r12) goto L4d
            r14 = r11[r13]
            if (r14 == 0) goto L4a
            r14.c()
        L4a:
            int r13 = r13 + 1
            goto L41
        L4d:
            long r6 = r6 >> r9
            int r10 = r10 + 1
            goto L2b
        L51:
            if (r8 != r9) goto L58
        L53:
            if (r5 == r3) goto L58
            int r5 = r5 + 1
            goto L11
        L58:
            r0.a()
        L5b:
            androidx.compose.foundation.lazy.layout.O r0 = androidx.compose.foundation.lazy.layout.O.a
            r15.b = r0
            r0 = -1
            r15.c = r0
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.lazy.layout.K.f():void");
    }

    public final void g(V v, boolean z) {
        Object objF = this.a.f(v.getKey());
        Intrinsics.d(objF);
        E[] eArr = ((H) objF).a;
        int length = eArr.length;
        int i = 0;
        int i2 = 0;
        while (i < length) {
            E e = eArr[i];
            int i3 = i2 + 1;
            if (e != null) {
                long jI = v.i(i2);
                long j = e.l;
                if (!androidx.compose.ui.unit.h.b(j, E.s) && !androidx.compose.ui.unit.h.b(j, jI)) {
                    long jC = androidx.compose.ui.unit.h.c(jI, j);
                    C0253l0 c0253l0 = e.e;
                    if (c0253l0 != null) {
                        long jC2 = androidx.compose.ui.unit.h.c(((androidx.compose.ui.unit.h) ((L0) e.q).getValue()).a, jC);
                        e.g(jC2);
                        e.f(true);
                        e.g = z;
                        kotlinx.coroutines.E.A(e.a, null, null, new C0453z(e, c0253l0, jC2, null), 3);
                    }
                }
                e.l = jI;
            }
            i++;
            i2 = i3;
        }
    }
}

package androidx.constraintlayout.compose;

import android.util.Log;
import androidx.collection.C0212j;
import androidx.compose.runtime.C0775b0;
import androidx.compose.ui.layout.AbstractC0897s;
import androidx.compose.ui.layout.J;
import androidx.compose.ui.layout.V;
import androidx.compose.ui.layout.W;
import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;

/* loaded from: classes.dex */
public final class j implements androidx.constraintlayout.core.widgets.analyzer.c {
    public final androidx.constraintlayout.core.widgets.f a;
    public LinkedHashMap b;
    public final LinkedHashMap c;
    public final LinkedHashMap d;
    public final k e;
    public final int[] f;
    public final int[] g;

    public j(androidx.compose.ui.unit.b bVar) {
        androidx.constraintlayout.core.widgets.f fVar = new androidx.constraintlayout.core.widgets.f(0, 0);
        fVar.t0 = new ArrayList();
        fVar.u0 = new com.quizlet.data.repository.course.membership.c(fVar);
        fVar.v0 = new androidx.constraintlayout.core.widgets.analyzer.f(fVar);
        fVar.x0 = null;
        fVar.y0 = false;
        fVar.z0 = new androidx.constraintlayout.core.c();
        fVar.C0 = 0;
        fVar.D0 = 0;
        fVar.E0 = new androidx.constraintlayout.core.widgets.b[4];
        fVar.F0 = new androidx.constraintlayout.core.widgets.b[4];
        fVar.G0 = 257;
        fVar.H0 = false;
        fVar.I0 = false;
        fVar.J0 = null;
        fVar.K0 = null;
        fVar.L0 = null;
        fVar.M0 = null;
        fVar.N0 = new HashSet();
        fVar.O0 = new androidx.constraintlayout.core.widgets.analyzer.b();
        fVar.x0 = this;
        fVar.v0.h = this;
        this.a = fVar;
        this.b = new LinkedHashMap();
        this.c = new LinkedHashMap();
        this.d = new LinkedHashMap();
        this.e = new k(bVar);
        this.f = new int[2];
        this.g = new int[2];
    }

    public static void d(androidx.constraintlayout.core.widgets.d dVar, int i, int i2, int i3, boolean z, boolean z2, int i4, int[] iArr) {
        int iOrdinal = dVar.ordinal();
        if (iOrdinal == 0) {
            iArr[0] = i;
            iArr[1] = i;
            return;
        }
        if (iOrdinal == 1) {
            iArr[0] = 0;
            iArr[1] = i4;
            return;
        }
        if (iOrdinal == 2) {
            boolean z3 = z2 || ((i3 == 1 || i3 == 2) && (i3 == 2 || i2 != 1 || z));
            iArr[0] = z3 ? i : 0;
            if (!z3) {
                i = i4;
            }
            iArr[1] = i;
            return;
        }
        if (iOrdinal == 3) {
            iArr[0] = i4;
            iArr[1] = i4;
        } else {
            throw new IllegalStateException((dVar + " is not supported").toString());
        }
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.c
    public final void a() {
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:29:0x00af  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x019a  */
    /* JADX WARN: Type inference failed for: r18v1 */
    /* JADX WARN: Type inference failed for: r18v2 */
    /* JADX WARN: Type inference failed for: r18v3 */
    @Override // androidx.constraintlayout.core.widgets.analyzer.c
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b(androidx.constraintlayout.core.widgets.e r28, androidx.constraintlayout.core.widgets.analyzer.b r29) {
        /*
            Method dump skipped, instructions count: 498
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.compose.j.b(androidx.constraintlayout.core.widgets.e, androidx.constraintlayout.core.widgets.analyzer.b):void");
    }

    public final long c(androidx.constraintlayout.core.widgets.e eVar, long j) {
        Object obj = eVar.i0;
        String str = eVar.k;
        int i = 0;
        if (eVar instanceof androidx.constraintlayout.core.widgets.l) {
            int i2 = androidx.compose.ui.unit.a.f(j) ? 1073741824 : androidx.compose.ui.unit.a.d(j) ? Integer.MIN_VALUE : 0;
            if (androidx.compose.ui.unit.a.e(j)) {
                i = 1073741824;
            } else if (androidx.compose.ui.unit.a.c(j)) {
                i = Integer.MIN_VALUE;
            }
            androidx.constraintlayout.core.widgets.l lVar = (androidx.constraintlayout.core.widgets.l) eVar;
            lVar.Y(i2, androidx.compose.ui.unit.a.h(j), i, androidx.compose.ui.unit.a.g(j));
            return C0212j.a(lVar.C0, lVar.D0);
        }
        if (obj instanceof J) {
            W wB = ((J) obj).B(j);
            this.b.put(obj, wB);
            return C0212j.a(wB.a, wB.b);
        }
        Log.w("CCL", "Nothing to measure for widget: " + str);
        return C0212j.a(0, 0);
    }

    public final void e(V v, List list, LinkedHashMap linkedHashMap) {
        String string;
        W w;
        String string2;
        this.b = linkedHashMap;
        LinkedHashMap linkedHashMap2 = this.d;
        if (linkedHashMap2.isEmpty()) {
            ArrayList arrayList = this.a.t0;
            int size = arrayList.size();
            for (int i = 0; i < size; i++) {
                androidx.constraintlayout.core.widgets.e eVar = (androidx.constraintlayout.core.widgets.e) arrayList.get(i);
                Object obj = eVar.i0;
                if (obj instanceof J) {
                    androidx.constraintlayout.core.state.k kVar = eVar.j;
                    androidx.constraintlayout.core.widgets.e eVar2 = kVar.a;
                    if (eVar2 != null) {
                        kVar.b = eVar2.s();
                        kVar.c = eVar2.t();
                        eVar2.s();
                        eVar2.t();
                        kVar.a(eVar2.j);
                    }
                    androidx.constraintlayout.core.state.k kVar2 = new androidx.constraintlayout.core.state.k(kVar);
                    J j = (J) obj;
                    Object objH = AbstractC0897s.h(j);
                    if (objH == null) {
                        j.G();
                        objH = null;
                    }
                    if (objH == null || (string2 = objH.toString()) == null) {
                        string2 = "null";
                    }
                    linkedHashMap2.put(string2, kVar2);
                }
            }
        }
        int size2 = list.size();
        for (int i2 = 0; i2 < size2; i2++) {
            J j2 = (J) list.get(i2);
            Object objH2 = AbstractC0897s.h(j2);
            if (objH2 == null) {
                j2.G();
                objH2 = null;
            }
            if (objH2 == null || (string = objH2.toString()) == null) {
                string = "null";
            }
            androidx.constraintlayout.core.state.k kVar3 = (androidx.constraintlayout.core.state.k) linkedHashMap2.get(string);
            if (kVar3 != null && (w = (W) this.b.get(j2)) != null && kVar3.o != 8) {
                if (Float.isNaN(kVar3.f) && Float.isNaN(kVar3.g) && Float.isNaN(kVar3.h) && Float.isNaN(kVar3.i) && Float.isNaN(kVar3.j) && Float.isNaN(kVar3.k) && Float.isNaN(kVar3.l) && Float.isNaN(kVar3.m) && Float.isNaN(kVar3.n)) {
                    int i3 = (int) 0;
                    V.e(v, w, P5.b(kVar3.b - i3, kVar3.c - i3));
                } else {
                    C0775b0 c0775b0 = new C0775b0(kVar3, 29);
                    int i4 = (int) 0;
                    int i5 = kVar3.b - i4;
                    int i6 = kVar3.c - i4;
                    float f = Float.isNaN(kVar3.k) ? DefinitionKt.NO_Float_VALUE : kVar3.k;
                    v.getClass();
                    long jB = P5.b(i5, i6);
                    V.a(v, w);
                    w.s0(androidx.compose.ui.unit.h.d(jB, w.e), f, c0775b0);
                }
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:108:0x02a9  */
    /* JADX WARN: Removed duplicated region for block: B:117:0x0164 A[EDGE_INSN: B:117:0x0164->B:51:0x0164 BREAK  A[LOOP:2: B:43:0x013c->B:119:0x013c], SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:38:0x00cc  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x00dc A[LOOP:1: B:39:0x00d6->B:41:0x00dc, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:45:0x0144  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x0172  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x01b0  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x01ed  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x0235  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final long f(long r17, androidx.compose.ui.unit.k r19, androidx.constraintlayout.compose.i r20, java.util.List r21, java.util.LinkedHashMap r22) {
        /*
            Method dump skipped, instructions count: 764
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.compose.j.f(long, androidx.compose.ui.unit.k, androidx.constraintlayout.compose.i, java.util.List, java.util.LinkedHashMap):long");
    }
}

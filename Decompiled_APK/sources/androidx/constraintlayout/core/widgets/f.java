package androidx.constraintlayout.core.widgets;

import androidx.constraintlayout.core.widgets.analyzer.n;
import androidx.constraintlayout.core.widgets.analyzer.p;
import com.skydoves.balloon.internals.DefinitionKt;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;

/* loaded from: classes.dex */
public final class f extends e {
    public int A0;
    public int B0;
    public int w0;
    public ArrayList t0 = new ArrayList();
    public com.quizlet.data.repository.course.membership.c u0 = new com.quizlet.data.repository.course.membership.c(this);
    public androidx.constraintlayout.core.widgets.analyzer.f v0 = new androidx.constraintlayout.core.widgets.analyzer.f(this);
    public androidx.constraintlayout.core.widgets.analyzer.c x0 = null;
    public boolean y0 = false;
    public androidx.constraintlayout.core.c z0 = new androidx.constraintlayout.core.c();
    public int C0 = 0;
    public int D0 = 0;
    public b[] E0 = new b[4];
    public b[] F0 = new b[4];
    public int G0 = 257;
    public boolean H0 = false;
    public boolean I0 = false;
    public WeakReference J0 = null;
    public WeakReference K0 = null;
    public WeakReference L0 = null;
    public WeakReference M0 = null;
    public HashSet N0 = new HashSet();
    public androidx.constraintlayout.core.widgets.analyzer.b O0 = new androidx.constraintlayout.core.widgets.analyzer.b();

    public static void b0(e eVar, androidx.constraintlayout.core.widgets.analyzer.c cVar, androidx.constraintlayout.core.widgets.analyzer.b bVar) {
        int i;
        int i2;
        if (cVar == null) {
            return;
        }
        if (eVar.j0 == 8 || (eVar instanceof i) || (eVar instanceof a)) {
            bVar.e = 0;
            bVar.f = 0;
            return;
        }
        d[] dVarArr = eVar.V;
        bVar.a = dVarArr[0];
        bVar.b = dVarArr[1];
        bVar.c = eVar.r();
        bVar.d = eVar.l();
        bVar.i = false;
        bVar.j = 0;
        d dVar = bVar.a;
        d dVar2 = d.c;
        boolean z = dVar == dVar2;
        boolean z2 = bVar.b == dVar2;
        boolean z3 = z && eVar.Z > DefinitionKt.NO_Float_VALUE;
        boolean z4 = z2 && eVar.Z > DefinitionKt.NO_Float_VALUE;
        d dVar3 = d.b;
        d dVar4 = d.a;
        if (z && eVar.u(0) && eVar.s == 0 && !z3) {
            bVar.a = dVar3;
            if (z2 && eVar.t == 0) {
                bVar.a = dVar4;
            }
            z = false;
        }
        if (z2 && eVar.u(1) && eVar.t == 0 && !z4) {
            bVar.b = dVar3;
            if (z && eVar.s == 0) {
                bVar.b = dVar4;
            }
            z2 = false;
        }
        if (eVar.B()) {
            bVar.a = dVar4;
            z = false;
        }
        if (eVar.C()) {
            bVar.b = dVar4;
            z2 = false;
        }
        int[] iArr = eVar.u;
        if (z3) {
            if (iArr[0] == 4) {
                bVar.a = dVar4;
            } else if (!z2) {
                if (bVar.b == dVar4) {
                    i2 = bVar.d;
                } else {
                    bVar.a = dVar3;
                    cVar.b(eVar, bVar);
                    i2 = bVar.f;
                }
                bVar.a = dVar4;
                bVar.c = (int) (eVar.Z * i2);
            }
        }
        if (z4) {
            if (iArr[1] == 4) {
                bVar.b = dVar4;
            } else if (!z) {
                if (bVar.a == dVar4) {
                    i = bVar.c;
                } else {
                    bVar.b = dVar3;
                    cVar.b(eVar, bVar);
                    i = bVar.e;
                }
                bVar.b = dVar4;
                if (eVar.a0 == -1) {
                    bVar.d = (int) (i / eVar.Z);
                } else {
                    bVar.d = (int) (eVar.Z * i);
                }
            }
        }
        cVar.b(eVar, bVar);
        eVar.S(bVar.e);
        eVar.N(bVar.f);
        eVar.F = bVar.h;
        eVar.J(bVar.g);
        bVar.j = 0;
    }

    @Override // androidx.constraintlayout.core.widgets.e
    public final void D() {
        this.z0.t();
        this.A0 = 0;
        this.B0 = 0;
        this.t0.clear();
        super.D();
    }

    @Override // androidx.constraintlayout.core.widgets.e
    public final void G(com.quizlet.data.interactor.set.c cVar) {
        super.G(cVar);
        int size = this.t0.size();
        for (int i = 0; i < size; i++) {
            ((e) this.t0.get(i)).G(cVar);
        }
    }

    @Override // androidx.constraintlayout.core.widgets.e
    public final void T(boolean z, boolean z2) {
        super.T(z, z2);
        int size = this.t0.size();
        for (int i = 0; i < size; i++) {
            ((e) this.t0.get(i)).T(z, z2);
        }
    }

    public final void V(e eVar) {
        this.t0.add(eVar);
        e eVar2 = eVar.W;
        if (eVar2 != null) {
            ((f) eVar2).t0.remove(eVar);
            eVar.D();
        }
        eVar.W = this;
    }

    public final void W(e eVar, int i) {
        if (i == 0) {
            int i2 = this.C0 + 1;
            b[] bVarArr = this.F0;
            if (i2 >= bVarArr.length) {
                this.F0 = (b[]) Arrays.copyOf(bVarArr, bVarArr.length * 2);
            }
            b[] bVarArr2 = this.F0;
            int i3 = this.C0;
            bVarArr2[i3] = new b(eVar, 0, this.y0);
            this.C0 = i3 + 1;
            return;
        }
        if (i == 1) {
            int i4 = this.D0 + 1;
            b[] bVarArr3 = this.E0;
            if (i4 >= bVarArr3.length) {
                this.E0 = (b[]) Arrays.copyOf(bVarArr3, bVarArr3.length * 2);
            }
            b[] bVarArr4 = this.E0;
            int i5 = this.D0;
            bVarArr4[i5] = new b(eVar, 1, this.y0);
            this.D0 = i5 + 1;
        }
    }

    public final void X(androidx.constraintlayout.core.c cVar) {
        f fVar;
        androidx.constraintlayout.core.c cVar2;
        boolean zC0 = c0(64);
        c(cVar, zC0);
        int size = this.t0.size();
        boolean z = false;
        for (int i = 0; i < size; i++) {
            e eVar = (e) this.t0.get(i);
            boolean[] zArr = eVar.U;
            zArr[0] = false;
            zArr[1] = false;
            if (eVar instanceof a) {
                z = true;
            }
        }
        if (z) {
            for (int i2 = 0; i2 < size; i2++) {
                e eVar2 = (e) this.t0.get(i2);
                if (eVar2 instanceof a) {
                    a aVar = (a) eVar2;
                    for (int i3 = 0; i3 < aVar.u0; i3++) {
                        e eVar3 = aVar.t0[i3];
                        if (aVar.w0 || eVar3.d()) {
                            int i4 = aVar.v0;
                            if (i4 == 0 || i4 == 1) {
                                eVar3.U[0] = true;
                            } else if (i4 == 2 || i4 == 3) {
                                eVar3.U[1] = true;
                            }
                        }
                    }
                }
            }
        }
        HashSet hashSet = this.N0;
        hashSet.clear();
        for (int i5 = 0; i5 < size; i5++) {
            e eVar4 = (e) this.t0.get(i5);
            eVar4.getClass();
            boolean z2 = eVar4 instanceof l;
            if (z2 || (eVar4 instanceof i)) {
                if (z2) {
                    hashSet.add(eVar4);
                } else {
                    eVar4.c(cVar, zC0);
                }
            }
        }
        while (hashSet.size() > 0) {
            int size2 = hashSet.size();
            Iterator it2 = hashSet.iterator();
            while (true) {
                if (!it2.hasNext()) {
                    break;
                }
                l lVar = (l) ((e) it2.next());
                for (int i6 = 0; i6 < lVar.u0; i6++) {
                    if (hashSet.contains(lVar.t0[i6])) {
                        lVar.c(cVar, zC0);
                        hashSet.remove(lVar);
                        break;
                    }
                }
            }
            if (size2 == hashSet.size()) {
                Iterator it3 = hashSet.iterator();
                while (it3.hasNext()) {
                    ((e) it3.next()).c(cVar, zC0);
                }
                hashSet.clear();
            }
        }
        boolean z3 = androidx.constraintlayout.core.c.q;
        d dVar = d.b;
        if (z3) {
            HashSet hashSet2 = new HashSet();
            for (int i7 = 0; i7 < size; i7++) {
                e eVar5 = (e) this.t0.get(i7);
                eVar5.getClass();
                if (!(eVar5 instanceof l) && !(eVar5 instanceof i)) {
                    hashSet2.add(eVar5);
                }
            }
            fVar = this;
            cVar2 = cVar;
            fVar.b(this, cVar2, hashSet2, this.V[0] == dVar ? 0 : 1, false);
            Iterator it4 = hashSet2.iterator();
            while (it4.hasNext()) {
                e eVar6 = (e) it4.next();
                k.b(this, cVar2, eVar6);
                eVar6.c(cVar2, zC0);
            }
        } else {
            fVar = this;
            cVar2 = cVar;
            for (int i8 = 0; i8 < size; i8++) {
                e eVar7 = (e) fVar.t0.get(i8);
                if (eVar7 instanceof f) {
                    d[] dVarArr = eVar7.V;
                    d dVar2 = dVarArr[0];
                    d dVar3 = dVarArr[1];
                    d dVar4 = d.a;
                    if (dVar2 == dVar) {
                        eVar7.O(dVar4);
                    }
                    if (dVar3 == dVar) {
                        eVar7.Q(dVar4);
                    }
                    eVar7.c(cVar2, zC0);
                    if (dVar2 == dVar) {
                        eVar7.O(dVar2);
                    }
                    if (dVar3 == dVar) {
                        eVar7.Q(dVar3);
                    }
                } else {
                    k.b(this, cVar2, eVar7);
                    if (!(eVar7 instanceof l) && !(eVar7 instanceof i)) {
                        eVar7.c(cVar2, zC0);
                    }
                }
            }
        }
        if (fVar.C0 > 0) {
            k.a(this, cVar2, null, 0);
        }
        if (fVar.D0 > 0) {
            k.a(this, cVar2, null, 1);
        }
    }

    public final boolean Y(int i, boolean z) {
        boolean z2;
        d dVar;
        boolean z3;
        androidx.constraintlayout.core.widgets.analyzer.f fVar = this.v0;
        f fVar2 = (f) fVar.d;
        boolean z4 = false;
        d dVarK = fVar2.k(0);
        d dVarK2 = fVar2.k(1);
        int iS = fVar2.s();
        int iT = fVar2.t();
        ArrayList arrayList = (ArrayList) fVar.f;
        d dVar2 = d.a;
        if (z && (dVarK == (dVar = d.b) || dVarK2 == dVar)) {
            Iterator it2 = arrayList.iterator();
            while (true) {
                if (!it2.hasNext()) {
                    z3 = z;
                    break;
                }
                p pVar = (p) it2.next();
                if (pVar.f == i && !pVar.k()) {
                    z3 = false;
                    break;
                }
            }
            if (i == 0) {
                if (z3 && dVarK == dVar) {
                    fVar2.O(dVar2);
                    fVar2.S(fVar.m(fVar2, 0));
                    fVar2.d.e.d(fVar2.r());
                }
            } else if (z3 && dVarK2 == dVar) {
                fVar2.Q(dVar2);
                fVar2.N(fVar.m(fVar2, 1));
                fVar2.e.e.d(fVar2.l());
            }
        }
        d dVar3 = d.d;
        if (i == 0) {
            d dVar4 = fVar2.V[0];
            if (dVar4 == dVar2 || dVar4 == dVar3) {
                int iR = fVar2.r() + iS;
                fVar2.d.i.d(iR);
                fVar2.d.e.d(iR - iS);
                z2 = true;
            }
            z2 = false;
        } else {
            d dVar5 = fVar2.V[1];
            if (dVar5 == dVar2 || dVar5 == dVar3) {
                int iL = fVar2.l() + iT;
                fVar2.e.i.d(iL);
                fVar2.e.e.d(iL - iT);
                z2 = true;
            }
            z2 = false;
        }
        fVar.u();
        Iterator it3 = arrayList.iterator();
        while (it3.hasNext()) {
            p pVar2 = (p) it3.next();
            if (pVar2.f == i && (pVar2.b != fVar2 || pVar2.g)) {
                pVar2.e();
            }
        }
        Iterator it4 = arrayList.iterator();
        while (true) {
            if (!it4.hasNext()) {
                z4 = true;
                break;
            }
            p pVar3 = (p) it4.next();
            if (pVar3.f == i && (z2 || pVar3.b != fVar2)) {
                if (!pVar3.h.j || !pVar3.i.j || (!(pVar3 instanceof androidx.constraintlayout.core.widgets.analyzer.d) && !pVar3.e.j)) {
                    break;
                }
            }
        }
        fVar2.O(dVarK);
        fVar2.Q(dVarK2);
        return z4;
    }

    /* JADX WARN: Removed duplicated region for block: B:357:0x062a  */
    /* JADX WARN: Removed duplicated region for block: B:371:0x065d  */
    /* JADX WARN: Removed duplicated region for block: B:396:0x06ab  */
    /* JADX WARN: Removed duplicated region for block: B:401:0x06bc  */
    /* JADX WARN: Removed duplicated region for block: B:408:0x06cc  */
    /* JADX WARN: Removed duplicated region for block: B:411:0x06d6  */
    /* JADX WARN: Removed duplicated region for block: B:417:0x06f3  */
    /* JADX WARN: Removed duplicated region for block: B:448:0x075f  */
    /* JADX WARN: Removed duplicated region for block: B:494:0x0819  */
    /* JADX WARN: Removed duplicated region for block: B:503:0x0858  */
    /* JADX WARN: Removed duplicated region for block: B:509:0x0874 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:524:0x08dc  */
    /* JADX WARN: Removed duplicated region for block: B:527:0x08ee  */
    /* JADX WARN: Removed duplicated region for block: B:530:0x090a  */
    /* JADX WARN: Removed duplicated region for block: B:531:0x0916  */
    /* JADX WARN: Removed duplicated region for block: B:533:0x0919  */
    /* JADX WARN: Removed duplicated region for block: B:545:0x0951 A[PHI: r15 r26
  0x0951: PHI (r15v10 boolean) = (r15v9 boolean), (r15v14 boolean), (r15v14 boolean), (r15v14 boolean) binds: [B:532:0x0917, B:540:0x0939, B:541:0x093b, B:543:0x0941] A[DONT_GENERATE, DONT_INLINE]
  0x0951: PHI (r26v8 boolean) = (r26v7 boolean), (r26v9 boolean), (r26v9 boolean), (r26v9 boolean) binds: [B:532:0x0917, B:540:0x0939, B:541:0x093b, B:543:0x0941] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:547:0x0957  */
    /* JADX WARN: Removed duplicated region for block: B:551:0x0967  */
    /* JADX WARN: Removed duplicated region for block: B:627:0x0958 A[SYNTHETIC] */
    /* JADX WARN: Type inference failed for: r10v14 */
    /* JADX WARN: Type inference failed for: r10v15, types: [boolean] */
    /* JADX WARN: Type inference failed for: r10v17 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void Z() {
        /*
            Method dump skipped, instructions count: 2423
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.widgets.f.Z():void");
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void a0(int i, int i2, int i3, int i4, int i5, int i6, int i7) {
        float f;
        int i8;
        int i9;
        androidx.constraintlayout.core.widgets.analyzer.c cVar;
        int i10;
        int i11;
        boolean zY;
        ArrayList arrayList;
        int i12;
        int i13;
        boolean zL;
        androidx.constraintlayout.core.widgets.analyzer.c cVar2;
        boolean z;
        int i14;
        androidx.constraintlayout.core.widgets.analyzer.c cVar3;
        boolean z2;
        androidx.constraintlayout.core.widgets.analyzer.l lVar;
        n nVar;
        boolean z3;
        int i15;
        int i16;
        int i17;
        ArrayList arrayList2;
        int i18;
        boolean z4;
        boolean z5;
        this.A0 = i6;
        this.B0 = i7;
        com.quizlet.data.repository.course.membership.c cVar4 = this.u0;
        cVar4.getClass();
        androidx.constraintlayout.core.widgets.analyzer.c cVar5 = this.x0;
        int size = this.t0.size();
        int iR = r();
        int iL = l();
        boolean zC = k.c(i, 128);
        int i19 = (zC || k.c(i, 64)) ? 1 : 0;
        d dVar = d.c;
        if (i19 != 0) {
            for (int i20 = 0; i20 < size; i20++) {
                f = DefinitionKt.NO_Float_VALUE;
                e eVar = (e) this.t0.get(i20);
                d[] dVarArr = eVar.V;
                i8 = 0;
                boolean z6 = (dVarArr[0] == dVar) && (dVarArr[1] == dVar) && eVar.Z > DefinitionKt.NO_Float_VALUE;
                if ((eVar.y() && z6) || ((eVar.z() && z6) || (eVar instanceof l) || eVar.y() || eVar.z())) {
                    i19 = 0;
                    break;
                }
            }
            f = DefinitionKt.NO_Float_VALUE;
            i8 = 0;
        } else {
            f = DefinitionKt.NO_Float_VALUE;
            i8 = 0;
        }
        int i21 = i19 & (((i2 == 1073741824 && i4 == 1073741824) || zC) ? 1 : i8);
        d dVar2 = d.b;
        if (i21 != 0) {
            int iMin = Math.min(this.D[i8], i3);
            int iMin2 = Math.min(this.D[1], i5);
            if (i2 != 1073741824 || r() == iMin) {
                z3 = true;
            } else {
                S(iMin);
                z3 = true;
                this.v0.b = true;
            }
            if (i4 == 1073741824 && l() != iMin2) {
                N(iMin2);
                this.v0.b = z3;
            }
            androidx.constraintlayout.core.widgets.analyzer.f fVar = this.v0;
            if (i2 == 1073741824 && i4 == 1073741824) {
                boolean z7 = fVar.b;
                f fVar2 = (f) fVar.d;
                if (z7 || fVar.c) {
                    Iterator it2 = fVar2.t0.iterator();
                    while (it2.hasNext()) {
                        e eVar2 = (e) it2.next();
                        eVar2.i();
                        eVar2.a = i8;
                        eVar2.d.n();
                        eVar2.e.m();
                        i21 = i21;
                        i8 = 0;
                    }
                    i9 = i21;
                    fVar2.i();
                    i17 = 0;
                    fVar2.a = false;
                    fVar2.d.n();
                    fVar2.e.m();
                    fVar.c = false;
                } else {
                    i9 = i21;
                    i17 = i8;
                }
                fVar.i((f) fVar.e);
                fVar2.b0 = i17;
                fVar2.c0 = i17;
                d dVarK = fVar2.k(i17);
                d dVarK2 = fVar2.k(1);
                if (fVar.b) {
                    fVar.j();
                }
                int iS = fVar2.s();
                i10 = size;
                int iT = fVar2.t();
                cVar = cVar5;
                fVar2.d.h.d(iS);
                fVar2.e.h.d(iT);
                fVar.u();
                d dVar3 = d.a;
                ArrayList arrayList3 = (ArrayList) fVar.f;
                if (dVarK == dVar2 || dVarK2 == dVar2) {
                    if (zC) {
                        Iterator it3 = arrayList3.iterator();
                        while (true) {
                            if (it3.hasNext()) {
                                if (!((p) it3.next()).k()) {
                                    zC = false;
                                    break;
                                }
                            } else {
                                break;
                            }
                        }
                    }
                    if (zC && dVarK == dVar2) {
                        fVar2.O(dVar3);
                        arrayList2 = arrayList3;
                        i18 = iT;
                        fVar2.S(fVar.m(fVar2, 0));
                        fVar2.d.e.d(fVar2.r());
                    } else {
                        arrayList2 = arrayList3;
                        i18 = iT;
                    }
                    if (zC && dVarK2 == dVar2) {
                        fVar2.Q(dVar3);
                        fVar2.N(fVar.m(fVar2, 1));
                        fVar2.e.e.d(fVar2.l());
                    }
                } else {
                    arrayList2 = arrayList3;
                    i18 = iT;
                }
                d dVar4 = fVar2.V[0];
                d dVar5 = d.d;
                if (dVar4 == dVar3 || dVar4 == dVar5) {
                    int iR2 = fVar2.r() + iS;
                    fVar2.d.i.d(iR2);
                    fVar2.d.e.d(iR2 - iS);
                    fVar.u();
                    d dVar6 = fVar2.V[1];
                    if (dVar6 == dVar3 || dVar6 == dVar5) {
                        int iL2 = fVar2.l() + i18;
                        fVar2.e.i.d(iL2);
                        fVar2.e.e.d(iL2 - i18);
                    }
                    fVar.u();
                    z4 = true;
                } else {
                    z4 = false;
                }
                Iterator it4 = arrayList2.iterator();
                while (it4.hasNext()) {
                    p pVar = (p) it4.next();
                    if (pVar.b != fVar2 || pVar.g) {
                        pVar.e();
                    }
                }
                Iterator it5 = arrayList2.iterator();
                while (it5.hasNext()) {
                    p pVar2 = (p) it5.next();
                    if (z4 || pVar2.b != fVar2) {
                        if (!pVar2.h.j || ((!pVar2.i.j && !(pVar2 instanceof androidx.constraintlayout.core.widgets.analyzer.j)) || (!pVar2.e.j && !(pVar2 instanceof androidx.constraintlayout.core.widgets.analyzer.d) && !(pVar2 instanceof androidx.constraintlayout.core.widgets.analyzer.j)))) {
                            z5 = false;
                            break;
                        }
                    }
                }
                z5 = true;
                fVar2.O(dVarK);
                fVar2.Q(dVarK2);
                zY = z5;
                i16 = 1073741824;
                i11 = 2;
            } else {
                i9 = i21;
                cVar = cVar5;
                i10 = size;
                boolean z8 = fVar.b;
                f fVar3 = (f) fVar.d;
                if (z8) {
                    Iterator it6 = fVar3.t0.iterator();
                    while (it6.hasNext()) {
                        e eVar3 = (e) it6.next();
                        eVar3.i();
                        eVar3.a = false;
                        androidx.constraintlayout.core.widgets.analyzer.l lVar2 = eVar3.d;
                        lVar2.e.j = false;
                        lVar2.g = false;
                        lVar2.n();
                        n nVar2 = eVar3.e;
                        nVar2.e.j = false;
                        nVar2.g = false;
                        nVar2.m();
                    }
                    i15 = 0;
                    fVar3.i();
                    fVar3.a = false;
                    androidx.constraintlayout.core.widgets.analyzer.l lVar3 = fVar3.d;
                    lVar3.e.j = false;
                    lVar3.g = false;
                    lVar3.n();
                    n nVar3 = fVar3.e;
                    nVar3.e.j = false;
                    nVar3.g = false;
                    nVar3.m();
                    fVar.j();
                } else {
                    i15 = 0;
                }
                fVar.i((f) fVar.e);
                fVar3.b0 = i15;
                fVar3.c0 = i15;
                fVar3.d.h.d(i15);
                fVar3.e.h.d(i15);
                i16 = 1073741824;
                if (i2 == 1073741824) {
                    zY = Y(i15, zC);
                    i11 = 1;
                } else {
                    i11 = 0;
                    zY = true;
                }
                if (i4 == 1073741824) {
                    zY &= Y(1, zC);
                    i11++;
                }
            }
            if (zY) {
                T(i2 == i16, i4 == i16);
            }
        } else {
            i9 = i21;
            cVar = cVar5;
            i10 = size;
            i11 = 0;
            zY = false;
        }
        if (zY && i11 == 2) {
            return;
        }
        int i22 = this.G0;
        if (i10 > 0) {
            int size2 = this.t0.size();
            boolean zC0 = c0(64);
            androidx.constraintlayout.core.widgets.analyzer.c cVar6 = this.x0;
            for (int i23 = 0; i23 < size2; i23++) {
                e eVar4 = (e) this.t0.get(i23);
                if (!(eVar4 instanceof i) && !(eVar4 instanceof a) && !eVar4.H && (!zC0 || (lVar = eVar4.d) == null || (nVar = eVar4.e) == null || !lVar.e.j || !nVar.e.j)) {
                    d dVarK3 = eVar4.k(0);
                    d dVarK4 = eVar4.k(1);
                    boolean z9 = dVarK3 == dVar && eVar4.s != 1 && dVarK4 == dVar && eVar4.t != 1;
                    if (!z9 && c0(1) && !(eVar4 instanceof l)) {
                        if (dVarK3 == dVar && eVar4.s == 0 && dVarK4 != dVar && !eVar4.y()) {
                            z9 = true;
                        }
                        if (dVarK4 == dVar && eVar4.t == 0 && dVarK3 != dVar && !eVar4.y()) {
                            z9 = true;
                        }
                        if ((dVarK3 == dVar || dVarK4 == dVar) && eVar4.Z > f) {
                            z9 = true;
                        }
                    }
                    if (!z9) {
                        cVar4.l(0, eVar4, cVar6);
                    }
                }
            }
            cVar6.a();
        }
        cVar4.r(this);
        ArrayList arrayList4 = (ArrayList) cVar4.a;
        int size3 = arrayList4.size();
        if (i10 > 0) {
            cVar4.p(this, 0, iR, iL);
        }
        if (size3 > 0) {
            d[] dVarArr2 = this.V;
            boolean z10 = dVarArr2[0] == dVar2;
            boolean z11 = dVarArr2[1] == dVar2;
            int iR3 = r();
            f fVar4 = (f) cVar4.c;
            int iMax = Math.max(iR3, fVar4.e0);
            int iMax2 = Math.max(l(), fVar4.f0);
            int i24 = 0;
            boolean z12 = false;
            while (i24 < size3) {
                e eVar5 = (e) arrayList4.get(i24);
                if (eVar5 instanceof l) {
                    int iR4 = eVar5.r();
                    int iL3 = eVar5.l();
                    z = z11;
                    i14 = i24;
                    cVar3 = cVar;
                    boolean zL2 = z12 | cVar4.l(1, eVar5, cVar3);
                    int iR5 = eVar5.r();
                    int iL4 = eVar5.l();
                    if (iR5 != iR4) {
                        eVar5.S(iR5);
                        if (z10 && eVar5.s() + eVar5.X > iMax) {
                            iMax = Math.max(iMax, eVar5.j(4).e() + eVar5.s() + eVar5.X);
                        }
                        z2 = true;
                    } else {
                        z2 = zL2;
                    }
                    if (iL4 != iL3) {
                        eVar5.N(iL4);
                        if (z && eVar5.t() + eVar5.Y > iMax2) {
                            iMax2 = Math.max(iMax2, eVar5.j(5).e() + eVar5.t() + eVar5.Y);
                        }
                        z2 = true;
                    }
                    z12 = ((l) eVar5).B0 | z2;
                } else {
                    z = z11;
                    i14 = i24;
                    cVar3 = cVar;
                }
                i24 = i14 + 1;
                cVar = cVar3;
                z11 = z;
            }
            boolean z13 = z11;
            int i25 = 0;
            while (true) {
                androidx.constraintlayout.core.widgets.analyzer.c cVar7 = cVar;
                if (i25 >= 2) {
                    break;
                }
                boolean z14 = z12;
                int i26 = 0;
                while (i26 < size3) {
                    e eVar6 = (e) arrayList4.get(i26);
                    if ((!(eVar6 instanceof j) || (eVar6 instanceof l)) && !(eVar6 instanceof i)) {
                        arrayList = arrayList4;
                        if (eVar6.j0 != 8 && ((i9 == 0 || !eVar6.d.e.j || !eVar6.e.e.j) && !(eVar6 instanceof l))) {
                            int iR6 = eVar6.r();
                            int iL5 = eVar6.l();
                            i12 = size3;
                            int i27 = eVar6.d0;
                            i13 = i26;
                            zL = cVar4.l(i25 == 1 ? 2 : 1, eVar6, cVar7) | z14;
                            int iR7 = eVar6.r();
                            cVar2 = cVar7;
                            int iL6 = eVar6.l();
                            if (iR7 != iR6) {
                                eVar6.S(iR7);
                                if (z10 && eVar6.s() + eVar6.X > iMax) {
                                    iMax = Math.max(iMax, eVar6.j(4).e() + eVar6.s() + eVar6.X);
                                }
                                zL = true;
                            }
                            if (iL6 != iL5) {
                                eVar6.N(iL6);
                                if (z13 && eVar6.t() + eVar6.Y > iMax2) {
                                    iMax2 = Math.max(iMax2, eVar6.j(5).e() + eVar6.t() + eVar6.Y);
                                }
                                zL = true;
                            }
                            if (eVar6.F && i27 != eVar6.d0) {
                                zL = true;
                            }
                        }
                        size3 = i12;
                        z14 = zL;
                        cVar7 = cVar2;
                        i26 = i13 + 1;
                        arrayList4 = arrayList;
                    } else {
                        arrayList = arrayList4;
                    }
                    i12 = size3;
                    cVar2 = cVar7;
                    i13 = i26;
                    zL = z14;
                    size3 = i12;
                    z14 = zL;
                    cVar7 = cVar2;
                    i26 = i13 + 1;
                    arrayList4 = arrayList;
                }
                ArrayList arrayList5 = arrayList4;
                int i28 = size3;
                cVar = cVar7;
                if (!z14) {
                    break;
                }
                i25++;
                cVar4.p(this, i25, iR, iL);
                arrayList4 = arrayList5;
                size3 = i28;
                z12 = false;
            }
        }
        this.G0 = i22;
        androidx.constraintlayout.core.c.q = c0(com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH);
    }

    public final boolean c0(int i) {
        return (this.G0 & i) == i;
    }

    @Override // androidx.constraintlayout.core.widgets.e
    public final void o(StringBuilder sb) {
        sb.append(this.k + ":{\n");
        StringBuilder sb2 = new StringBuilder("  actualWidth:");
        sb2.append(this.X);
        sb.append(sb2.toString());
        sb.append("\n");
        sb.append("  actualHeight:" + this.Y);
        sb.append("\n");
        Iterator it2 = this.t0.iterator();
        while (it2.hasNext()) {
            ((e) it2.next()).o(sb);
            sb.append(",\n");
        }
        sb.append("}");
    }
}

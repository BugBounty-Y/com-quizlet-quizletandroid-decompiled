package androidx.constraintlayout.core.widgets.analyzer;

import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;

/* loaded from: classes.dex */
public abstract class i {
    public static final b a = new b();

    public static boolean a(androidx.constraintlayout.core.widgets.e eVar) {
        androidx.constraintlayout.core.widgets.d[] dVarArr = eVar.V;
        androidx.constraintlayout.core.widgets.d dVar = dVarArr[0];
        androidx.constraintlayout.core.widgets.d dVar2 = dVarArr[1];
        androidx.constraintlayout.core.widgets.e eVar2 = eVar.W;
        androidx.constraintlayout.core.widgets.f fVar = eVar2 != null ? (androidx.constraintlayout.core.widgets.f) eVar2 : null;
        androidx.constraintlayout.core.widgets.d dVar3 = androidx.constraintlayout.core.widgets.d.a;
        if (fVar != null) {
            androidx.constraintlayout.core.widgets.d dVar4 = fVar.V[0];
        }
        if (fVar != null) {
            androidx.constraintlayout.core.widgets.d dVar5 = fVar.V[1];
        }
        androidx.constraintlayout.core.widgets.d dVar6 = androidx.constraintlayout.core.widgets.d.c;
        androidx.constraintlayout.core.widgets.d dVar7 = androidx.constraintlayout.core.widgets.d.b;
        boolean z = dVar == dVar3 || eVar.B() || dVar == dVar7 || (dVar == dVar6 && eVar.s == 0 && eVar.Z == DefinitionKt.NO_Float_VALUE && eVar.u(0)) || (dVar == dVar6 && eVar.s == 1 && eVar.v(0, eVar.r()));
        boolean z2 = dVar2 == dVar3 || eVar.C() || dVar2 == dVar7 || (dVar2 == dVar6 && eVar.t == 0 && eVar.Z == DefinitionKt.NO_Float_VALUE && eVar.u(1)) || (dVar2 == dVar6 && eVar.t == 1 && eVar.v(1, eVar.l()));
        return (eVar.Z > DefinitionKt.NO_Float_VALUE && (z || z2)) || (z && z2);
    }

    public static o b(androidx.constraintlayout.core.widgets.e eVar, int i, ArrayList arrayList, o oVar) {
        int i2;
        int i3 = i == 0 ? eVar.r0 : eVar.s0;
        if (i3 != -1 && (oVar == null || i3 != oVar.b)) {
            int i4 = 0;
            while (true) {
                if (i4 >= arrayList.size()) {
                    break;
                }
                o oVar2 = (o) arrayList.get(i4);
                if (oVar2.b == i3) {
                    if (oVar != null) {
                        oVar.c(i, oVar2);
                        arrayList.remove(oVar);
                    }
                    oVar = oVar2;
                } else {
                    i4++;
                }
            }
        } else if (i3 != -1) {
            return oVar;
        }
        if (oVar == null) {
            if (eVar instanceof androidx.constraintlayout.core.widgets.j) {
                androidx.constraintlayout.core.widgets.j jVar = (androidx.constraintlayout.core.widgets.j) eVar;
                int i5 = 0;
                while (true) {
                    if (i5 >= jVar.u0) {
                        i2 = -1;
                        break;
                    }
                    androidx.constraintlayout.core.widgets.e eVar2 = jVar.t0[i5];
                    if ((i == 0 && (i2 = eVar2.r0) != -1) || (i == 1 && (i2 = eVar2.s0) != -1)) {
                        break;
                    }
                    i5++;
                }
                if (i2 != -1) {
                    int i6 = 0;
                    while (true) {
                        if (i6 >= arrayList.size()) {
                            break;
                        }
                        o oVar3 = (o) arrayList.get(i6);
                        if (oVar3.b == i2) {
                            oVar = oVar3;
                            break;
                        }
                        i6++;
                    }
                }
            }
            if (oVar == null) {
                oVar = new o();
                oVar.a = new ArrayList();
                oVar.d = null;
                oVar.e = -1;
                int i7 = o.f;
                o.f = i7 + 1;
                oVar.b = i7;
                oVar.c = i;
            }
            arrayList.add(oVar);
        }
        ArrayList arrayList2 = oVar.a;
        if (arrayList2.contains(eVar)) {
            return oVar;
        }
        arrayList2.add(eVar);
        if (eVar instanceof androidx.constraintlayout.core.widgets.i) {
            androidx.constraintlayout.core.widgets.i iVar = (androidx.constraintlayout.core.widgets.i) eVar;
            iVar.w0.c(iVar.x0 == 0 ? 1 : 0, oVar, arrayList);
        }
        int i8 = oVar.b;
        if (i == 0) {
            eVar.r0 = i8;
            eVar.K.c(i, oVar, arrayList);
            eVar.M.c(i, oVar, arrayList);
        } else {
            eVar.s0 = i8;
            eVar.L.c(i, oVar, arrayList);
            eVar.O.c(i, oVar, arrayList);
            eVar.N.c(i, oVar, arrayList);
        }
        eVar.R.c(i, oVar, arrayList);
        return oVar;
    }

    public static void c(int i, androidx.constraintlayout.core.widgets.e eVar, c cVar, boolean z) {
        androidx.constraintlayout.core.widgets.c cVar2;
        androidx.constraintlayout.core.widgets.c cVar3;
        char c;
        androidx.constraintlayout.core.widgets.c cVar4;
        androidx.constraintlayout.core.widgets.c cVar5;
        if (eVar.n) {
            return;
        }
        if (!(eVar instanceof androidx.constraintlayout.core.widgets.f) && eVar.A() && a(eVar)) {
            androidx.constraintlayout.core.widgets.f.b0(eVar, cVar, new b());
        }
        androidx.constraintlayout.core.widgets.c cVarJ = eVar.j(2);
        androidx.constraintlayout.core.widgets.c cVarJ2 = eVar.j(4);
        int iD = cVarJ.d();
        int iD2 = cVarJ2.d();
        HashSet hashSet = cVarJ.a;
        androidx.constraintlayout.core.widgets.d dVar = androidx.constraintlayout.core.widgets.d.c;
        if (hashSet != null && cVarJ.c) {
            Iterator it2 = hashSet.iterator();
            while (it2.hasNext()) {
                androidx.constraintlayout.core.widgets.c cVar6 = (androidx.constraintlayout.core.widgets.c) it2.next();
                androidx.constraintlayout.core.widgets.e eVar2 = cVar6.d;
                int i2 = i + 1;
                boolean zA = a(eVar2);
                if (eVar2.A() && zA) {
                    c = 0;
                    androidx.constraintlayout.core.widgets.f.b0(eVar2, cVar, new b());
                } else {
                    c = 0;
                }
                androidx.constraintlayout.core.widgets.c cVar7 = eVar2.K;
                androidx.constraintlayout.core.widgets.c cVar8 = eVar2.M;
                char c2 = ((cVar6 == cVar7 && (cVar5 = cVar8.f) != null && cVar5.c) || (cVar6 == cVar8 && (cVar4 = cVar7.f) != null && cVar4.c)) ? (char) 1 : c;
                androidx.constraintlayout.core.widgets.d dVar2 = eVar2.V[c];
                if (dVar2 != dVar || zA) {
                    if (!eVar2.A()) {
                        if (cVar6 == cVar7 && cVar8.f == null) {
                            int iE = cVar7.e() + iD;
                            eVar2.L(iE, eVar2.r() + iE);
                            c(i2, eVar2, cVar, z);
                        } else if (cVar6 == cVar8 && cVar7.f == null) {
                            int iE2 = iD - cVar8.e();
                            eVar2.L(iE2 - eVar2.r(), iE2);
                            c(i2, eVar2, cVar, z);
                        } else if (c2 != 0 && !eVar2.y()) {
                            d(i2, eVar2, cVar, z);
                        }
                    }
                } else if (dVar2 == dVar && eVar2.w >= 0 && eVar2.v >= 0 && (eVar2.j0 == 8 || (eVar2.s == 0 && eVar2.Z == DefinitionKt.NO_Float_VALUE))) {
                    if (!eVar2.y() && !eVar2.H && c2 != 0 && !eVar2.y()) {
                        e(i2, eVar, cVar, eVar2, z);
                    }
                }
            }
        }
        if (eVar instanceof androidx.constraintlayout.core.widgets.i) {
            return;
        }
        HashSet hashSet2 = cVarJ2.a;
        if (hashSet2 != null && cVarJ2.c) {
            Iterator it3 = hashSet2.iterator();
            while (it3.hasNext()) {
                androidx.constraintlayout.core.widgets.c cVar9 = (androidx.constraintlayout.core.widgets.c) it3.next();
                androidx.constraintlayout.core.widgets.e eVar3 = cVar9.d;
                int i3 = i + 1;
                boolean zA2 = a(eVar3);
                if (eVar3.A() && zA2) {
                    androidx.constraintlayout.core.widgets.f.b0(eVar3, cVar, new b());
                }
                androidx.constraintlayout.core.widgets.c cVar10 = eVar3.K;
                androidx.constraintlayout.core.widgets.c cVar11 = eVar3.M;
                boolean z2 = (cVar9 == cVar10 && (cVar3 = cVar11.f) != null && cVar3.c) || (cVar9 == cVar11 && (cVar2 = cVar10.f) != null && cVar2.c);
                androidx.constraintlayout.core.widgets.d dVar3 = eVar3.V[0];
                if (dVar3 != dVar || zA2) {
                    if (!eVar3.A()) {
                        if (cVar9 == cVar10 && cVar11.f == null) {
                            int iE3 = cVar10.e() + iD2;
                            eVar3.L(iE3, eVar3.r() + iE3);
                            c(i3, eVar3, cVar, z);
                        } else if (cVar9 == cVar11 && cVar10.f == null) {
                            int iE4 = iD2 - cVar11.e();
                            eVar3.L(iE4 - eVar3.r(), iE4);
                            c(i3, eVar3, cVar, z);
                        } else if (z2 && !eVar3.y()) {
                            d(i3, eVar3, cVar, z);
                        }
                    }
                } else if (dVar3 == dVar && eVar3.w >= 0 && eVar3.v >= 0) {
                    if (eVar3.j0 == 8 || (eVar3.s == 0 && eVar3.Z == DefinitionKt.NO_Float_VALUE)) {
                        if (!eVar3.y() && !eVar3.H && z2 && !eVar3.y()) {
                            e(i3, eVar, cVar, eVar3, z);
                        }
                    }
                }
            }
        }
        eVar.n = true;
    }

    public static void d(int i, androidx.constraintlayout.core.widgets.e eVar, c cVar, boolean z) {
        float f = eVar.g0;
        androidx.constraintlayout.core.widgets.c cVar2 = eVar.K;
        int iD = cVar2.f.d();
        androidx.constraintlayout.core.widgets.c cVar3 = eVar.M;
        int iD2 = cVar3.f.d();
        int iE = cVar2.e() + iD;
        int iE2 = iD2 - cVar3.e();
        if (iD == iD2) {
            f = 0.5f;
        } else {
            iD = iE;
            iD2 = iE2;
        }
        int iR = eVar.r();
        int i2 = (iD2 - iD) - iR;
        if (iD > iD2) {
            i2 = (iD - iD2) - iR;
        }
        int i3 = ((int) (i2 > 0 ? (f * i2) + 0.5f : f * i2)) + iD;
        int i4 = i3 + iR;
        if (iD > iD2) {
            i4 = i3 - iR;
        }
        eVar.L(i3, i4);
        c(i + 1, eVar, cVar, z);
    }

    public static void e(int i, androidx.constraintlayout.core.widgets.e eVar, c cVar, androidx.constraintlayout.core.widgets.e eVar2, boolean z) {
        float f = eVar2.g0;
        androidx.constraintlayout.core.widgets.c cVar2 = eVar2.K;
        int iE = cVar2.e() + cVar2.f.d();
        androidx.constraintlayout.core.widgets.c cVar3 = eVar2.M;
        int iD = cVar3.f.d() - cVar3.e();
        if (iD >= iE) {
            int iR = eVar2.r();
            if (eVar2.j0 != 8) {
                int i2 = eVar2.s;
                if (i2 == 2) {
                    iR = (int) (eVar2.g0 * 0.5f * (eVar instanceof androidx.constraintlayout.core.widgets.f ? eVar.r() : eVar.W.r()));
                } else if (i2 == 0) {
                    iR = iD - iE;
                }
                iR = Math.max(eVar2.v, iR);
                int i3 = eVar2.w;
                if (i3 > 0) {
                    iR = Math.min(i3, iR);
                }
            }
            int i4 = iE + ((int) ((f * ((iD - iE) - iR)) + 0.5f));
            eVar2.L(i4, iR + i4);
            c(i + 1, eVar2, cVar, z);
        }
    }

    public static void f(int i, androidx.constraintlayout.core.widgets.e eVar, c cVar) {
        float f = eVar.h0;
        androidx.constraintlayout.core.widgets.c cVar2 = eVar.L;
        int iD = cVar2.f.d();
        androidx.constraintlayout.core.widgets.c cVar3 = eVar.N;
        int iD2 = cVar3.f.d();
        int iE = cVar2.e() + iD;
        int iE2 = iD2 - cVar3.e();
        if (iD == iD2) {
            f = 0.5f;
        } else {
            iD = iE;
            iD2 = iE2;
        }
        int iL = eVar.l();
        int i2 = (iD2 - iD) - iL;
        if (iD > iD2) {
            i2 = (iD - iD2) - iL;
        }
        int i3 = (int) (i2 > 0 ? (f * i2) + 0.5f : f * i2);
        int i4 = iD + i3;
        int i5 = i4 + iL;
        if (iD > iD2) {
            i4 = iD - i3;
            i5 = i4 - iL;
        }
        eVar.M(i4, i5);
        i(i + 1, eVar, cVar);
    }

    public static void g(int i, androidx.constraintlayout.core.widgets.e eVar, c cVar, androidx.constraintlayout.core.widgets.e eVar2) {
        float f = eVar2.h0;
        androidx.constraintlayout.core.widgets.c cVar2 = eVar2.L;
        int iE = cVar2.e() + cVar2.f.d();
        androidx.constraintlayout.core.widgets.c cVar3 = eVar2.N;
        int iD = cVar3.f.d() - cVar3.e();
        if (iD >= iE) {
            int iL = eVar2.l();
            if (eVar2.j0 != 8) {
                int i2 = eVar2.t;
                if (i2 == 2) {
                    iL = (int) (f * 0.5f * (eVar instanceof androidx.constraintlayout.core.widgets.f ? eVar.l() : eVar.W.l()));
                } else if (i2 == 0) {
                    iL = iD - iE;
                }
                iL = Math.max(eVar2.y, iL);
                int i3 = eVar2.z;
                if (i3 > 0) {
                    iL = Math.min(i3, iL);
                }
            }
            int i4 = iE + ((int) ((f * ((iD - iE) - iL)) + 0.5f));
            eVar2.M(i4, iL + i4);
            i(i + 1, eVar2, cVar);
        }
    }

    public static boolean h(androidx.constraintlayout.core.widgets.d dVar, androidx.constraintlayout.core.widgets.d dVar2, androidx.constraintlayout.core.widgets.d dVar3, androidx.constraintlayout.core.widgets.d dVar4) {
        androidx.constraintlayout.core.widgets.d dVar5 = androidx.constraintlayout.core.widgets.d.a;
        androidx.constraintlayout.core.widgets.d dVar6 = androidx.constraintlayout.core.widgets.d.d;
        androidx.constraintlayout.core.widgets.d dVar7 = androidx.constraintlayout.core.widgets.d.b;
        return (dVar3 == dVar5 || dVar3 == dVar7 || (dVar3 == dVar6 && dVar != dVar7)) || (dVar4 == dVar5 || dVar4 == dVar7 || (dVar4 == dVar6 && dVar2 != dVar7));
    }

    public static void i(int i, androidx.constraintlayout.core.widgets.e eVar, c cVar) {
        boolean z;
        androidx.constraintlayout.core.widgets.c cVar2;
        androidx.constraintlayout.core.widgets.c cVar3;
        androidx.constraintlayout.core.widgets.c cVar4;
        androidx.constraintlayout.core.widgets.c cVar5;
        if (eVar.o) {
            return;
        }
        if (!(eVar instanceof androidx.constraintlayout.core.widgets.f) && eVar.A() && a(eVar)) {
            androidx.constraintlayout.core.widgets.f.b0(eVar, cVar, new b());
        }
        androidx.constraintlayout.core.widgets.c cVarJ = eVar.j(3);
        androidx.constraintlayout.core.widgets.c cVarJ2 = eVar.j(5);
        int iD = cVarJ.d();
        int iD2 = cVarJ2.d();
        HashSet hashSet = cVarJ.a;
        androidx.constraintlayout.core.widgets.d dVar = androidx.constraintlayout.core.widgets.d.c;
        if (hashSet != null && cVarJ.c) {
            Iterator it2 = hashSet.iterator();
            while (it2.hasNext()) {
                androidx.constraintlayout.core.widgets.c cVar6 = (androidx.constraintlayout.core.widgets.c) it2.next();
                androidx.constraintlayout.core.widgets.e eVar2 = cVar6.d;
                int i2 = i + 1;
                boolean zA = a(eVar2);
                if (eVar2.A() && zA) {
                    androidx.constraintlayout.core.widgets.f.b0(eVar2, cVar, new b());
                }
                androidx.constraintlayout.core.widgets.c cVar7 = eVar2.L;
                androidx.constraintlayout.core.widgets.c cVar8 = eVar2.N;
                boolean z2 = (cVar6 == cVar7 && (cVar5 = cVar8.f) != null && cVar5.c) || (cVar6 == cVar8 && (cVar4 = cVar7.f) != null && cVar4.c);
                androidx.constraintlayout.core.widgets.d dVar2 = eVar2.V[1];
                if (dVar2 != dVar || zA) {
                    if (!eVar2.A()) {
                        if (cVar6 == cVar7 && cVar8.f == null) {
                            int iE = cVar7.e() + iD;
                            eVar2.M(iE, eVar2.l() + iE);
                            i(i2, eVar2, cVar);
                        } else if (cVar6 == cVar8 && cVar7.f == null) {
                            int iE2 = iD - cVar8.e();
                            eVar2.M(iE2 - eVar2.l(), iE2);
                            i(i2, eVar2, cVar);
                        } else if (z2 && !eVar2.z()) {
                            f(i2, eVar2, cVar);
                        }
                    }
                } else if (dVar2 == dVar && eVar2.z >= 0 && eVar2.y >= 0 && (eVar2.j0 == 8 || (eVar2.t == 0 && eVar2.Z == DefinitionKt.NO_Float_VALUE))) {
                    if (!eVar2.z() && !eVar2.H && z2 && !eVar2.z()) {
                        g(i2, eVar, cVar, eVar2);
                    }
                }
            }
        }
        boolean z3 = true;
        z3 = true;
        z3 = true;
        if (eVar instanceof androidx.constraintlayout.core.widgets.i) {
            return;
        }
        HashSet hashSet2 = cVarJ2.a;
        if (hashSet2 != null && cVarJ2.c) {
            Iterator it3 = hashSet2.iterator();
            while (it3.hasNext()) {
                androidx.constraintlayout.core.widgets.c cVar9 = (androidx.constraintlayout.core.widgets.c) it3.next();
                androidx.constraintlayout.core.widgets.e eVar3 = cVar9.d;
                int i3 = i + 1;
                boolean zA2 = a(eVar3);
                if (eVar3.A() && zA2) {
                    androidx.constraintlayout.core.widgets.f.b0(eVar3, cVar, new b());
                }
                androidx.constraintlayout.core.widgets.c cVar10 = eVar3.L;
                androidx.constraintlayout.core.widgets.c cVar11 = eVar3.N;
                boolean z4 = (cVar9 == cVar10 && (cVar3 = cVar11.f) != null && cVar3.c) || (cVar9 == cVar11 && (cVar2 = cVar10.f) != null && cVar2.c);
                androidx.constraintlayout.core.widgets.d dVar3 = eVar3.V[1];
                if (dVar3 != dVar || zA2) {
                    if (!eVar3.A()) {
                        if (cVar9 == cVar10 && cVar11.f == null) {
                            int iE3 = cVar10.e() + iD2;
                            eVar3.M(iE3, eVar3.l() + iE3);
                            i(i3, eVar3, cVar);
                        } else if (cVar9 == cVar11 && cVar10.f == null) {
                            int iE4 = iD2 - cVar11.e();
                            eVar3.M(iE4 - eVar3.l(), iE4);
                            i(i3, eVar3, cVar);
                        } else if (z4 && !eVar3.z()) {
                            f(i3, eVar3, cVar);
                        }
                    }
                } else if (dVar3 == dVar && eVar3.z >= 0 && eVar3.y >= 0 && (eVar3.j0 == 8 || (eVar3.t == 0 && eVar3.Z == DefinitionKt.NO_Float_VALUE))) {
                    if (!eVar3.z() && !eVar3.H && z4 && !eVar3.z()) {
                        g(i3, eVar, cVar, eVar3);
                    }
                }
            }
        }
        androidx.constraintlayout.core.widgets.c cVarJ3 = eVar.j(6);
        if (cVarJ3.a != null && cVarJ3.c) {
            int iD3 = cVarJ3.d();
            Iterator it4 = cVarJ3.a.iterator();
            while (it4.hasNext()) {
                androidx.constraintlayout.core.widgets.c cVar12 = (androidx.constraintlayout.core.widgets.c) it4.next();
                androidx.constraintlayout.core.widgets.e eVar4 = cVar12.d;
                int i4 = i + 1;
                boolean zA3 = a(eVar4);
                if (eVar4.A() && zA3) {
                    androidx.constraintlayout.core.widgets.f.b0(eVar4, cVar, new b());
                }
                if (eVar4.V[z3 ? 1 : 0] != dVar || zA3) {
                    if (!eVar4.A()) {
                        androidx.constraintlayout.core.widgets.c cVar13 = eVar4.O;
                        if (cVar12 == cVar13) {
                            int iE5 = cVar12.e() + iD3;
                            if (eVar4.F) {
                                int i5 = iE5 - eVar4.d0;
                                int i6 = eVar4.Y + i5;
                                eVar4.c0 = i5;
                                eVar4.L.l(i5);
                                eVar4.N.l(i6);
                                cVar13.l(iE5);
                                z = z3 ? 1 : 0;
                                eVar4.m = z;
                            } else {
                                z = z3 ? 1 : 0;
                            }
                            i(i4, eVar4, cVar);
                        }
                        z3 = z;
                    }
                }
                z = z3 ? 1 : 0;
                z3 = z;
            }
        }
        eVar.o = z3;
    }
}

package androidx.constraintlayout.core.widgets;

import java.util.ArrayList;

/* loaded from: classes.dex */
public final class h extends l {
    public e[] d1;
    public int G0 = -1;
    public int H0 = -1;
    public int I0 = -1;
    public int J0 = -1;
    public int K0 = -1;
    public int L0 = -1;
    public float M0 = 0.5f;
    public float N0 = 0.5f;
    public float O0 = 0.5f;
    public float P0 = 0.5f;
    public float Q0 = 0.5f;
    public float R0 = 0.5f;
    public int S0 = 0;
    public int T0 = 0;
    public int U0 = 2;
    public int V0 = 2;
    public int W0 = 0;
    public int X0 = -1;
    public int Y0 = 0;
    public final ArrayList Z0 = new ArrayList();
    public e[] a1 = null;
    public e[] b1 = null;
    public int[] c1 = null;
    public int e1 = 0;

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:395:0x06c4  */
    /* JADX WARN: Removed duplicated region for block: B:397:0x06c9  */
    /* JADX WARN: Removed duplicated region for block: B:404:0x06db  */
    /* JADX WARN: Removed duplicated region for block: B:405:0x06de  */
    /* JADX WARN: Removed duplicated region for block: B:412:0x06fa  */
    /* JADX WARN: Removed duplicated region for block: B:413:0x06fd  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x0116  */
    @Override // androidx.constraintlayout.core.widgets.l
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void Y(int r39, int r40, int r41, int r42) {
        /*
            Method dump skipped, instructions count: 1794
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.widgets.h.Y(int, int, int, int):void");
    }

    public final int a0(e eVar, int i) {
        e eVar2;
        if (eVar == null) {
            return 0;
        }
        if (eVar.V[1] == d.c) {
            int i2 = eVar.t;
            if (i2 == 0) {
                return 0;
            }
            if (i2 == 2) {
                int i3 = (int) (eVar.A * i);
                if (i3 != eVar.l()) {
                    eVar.g = true;
                    Z(eVar, eVar.V[0], eVar.r(), d.a, i3);
                }
                return i3;
            }
            eVar2 = eVar;
            if (i2 == 1) {
                return eVar2.l();
            }
            if (i2 == 3) {
                return (int) ((eVar2.r() * eVar2.Z) + 0.5f);
            }
        } else {
            eVar2 = eVar;
        }
        return eVar2.l();
    }

    public final int b0(e eVar, int i) {
        e eVar2;
        if (eVar == null) {
            return 0;
        }
        if (eVar.V[0] == d.c) {
            int i2 = eVar.s;
            if (i2 == 0) {
                return 0;
            }
            if (i2 == 2) {
                int i3 = (int) (eVar.x * i);
                if (i3 != eVar.r()) {
                    eVar.g = true;
                    Z(eVar, d.a, i3, eVar.V[1], eVar.l());
                }
                return i3;
            }
            eVar2 = eVar;
            if (i2 == 1) {
                return eVar2.r();
            }
            if (i2 == 3) {
                return (int) ((eVar2.l() * eVar2.Z) + 0.5f);
            }
        } else {
            eVar2 = eVar;
        }
        return eVar2.r();
    }

    @Override // androidx.constraintlayout.core.widgets.e
    public final void c(androidx.constraintlayout.core.c cVar, boolean z) {
        e eVar;
        float f;
        int i;
        super.c(cVar, z);
        e eVar2 = this.W;
        boolean z2 = eVar2 != null && ((f) eVar2).y0;
        int i2 = this.W0;
        ArrayList arrayList = this.Z0;
        if (i2 != 0) {
            if (i2 == 1) {
                int size = arrayList.size();
                int i3 = 0;
                while (i3 < size) {
                    ((g) arrayList.get(i3)).b(i3, z2, i3 == size + (-1));
                    i3++;
                }
            } else if (i2 != 2) {
                if (i2 == 3) {
                    int size2 = arrayList.size();
                    int i4 = 0;
                    while (i4 < size2) {
                        ((g) arrayList.get(i4)).b(i4, z2, i4 == size2 + (-1));
                        i4++;
                    }
                }
            } else if (this.c1 != null && this.b1 != null && this.a1 != null) {
                for (int i5 = 0; i5 < this.e1; i5++) {
                    this.d1[i5].E();
                }
                int[] iArr = this.c1;
                int i6 = iArr[0];
                int i7 = iArr[1];
                float f2 = this.M0;
                e eVar3 = null;
                int i8 = 0;
                while (i8 < i6) {
                    if (z2) {
                        i = (i6 - i8) - 1;
                        f = 1.0f - this.M0;
                    } else {
                        f = f2;
                        i = i8;
                    }
                    e eVar4 = this.b1[i];
                    if (eVar4 != null && eVar4.j0 != 8) {
                        c cVar2 = eVar4.K;
                        if (i8 == 0) {
                            eVar4.g(cVar2, this.K, this.z0);
                            eVar4.m0 = this.G0;
                            eVar4.g0 = f;
                        }
                        if (i8 == i6 - 1) {
                            eVar4.g(eVar4.M, this.M, this.A0);
                        }
                        if (i8 > 0 && eVar3 != null) {
                            int i9 = this.S0;
                            c cVar3 = eVar3.M;
                            eVar4.g(cVar2, cVar3, i9);
                            eVar3.g(cVar3, cVar2, 0);
                        }
                        eVar3 = eVar4;
                    }
                    i8++;
                    f2 = f;
                }
                for (int i10 = 0; i10 < i7; i10++) {
                    e eVar5 = this.a1[i10];
                    if (eVar5 != null && eVar5.j0 != 8) {
                        c cVar4 = eVar5.L;
                        if (i10 == 0) {
                            eVar5.g(cVar4, this.L, this.v0);
                            eVar5.n0 = this.H0;
                            eVar5.h0 = this.N0;
                        }
                        if (i10 == i7 - 1) {
                            eVar5.g(eVar5.N, this.N, this.w0);
                        }
                        if (i10 > 0 && eVar3 != null) {
                            int i11 = this.T0;
                            c cVar5 = eVar3.N;
                            eVar5.g(cVar4, cVar5, i11);
                            eVar3.g(cVar5, cVar4, 0);
                        }
                        eVar3 = eVar5;
                    }
                }
                for (int i12 = 0; i12 < i6; i12++) {
                    for (int i13 = 0; i13 < i7; i13++) {
                        int i14 = (i13 * i6) + i12;
                        if (this.Y0 == 1) {
                            i14 = (i12 * i7) + i13;
                        }
                        e[] eVarArr = this.d1;
                        if (i14 < eVarArr.length && (eVar = eVarArr[i14]) != null && eVar.j0 != 8) {
                            e eVar6 = this.b1[i12];
                            e eVar7 = this.a1[i13];
                            if (eVar != eVar6) {
                                eVar.g(eVar.K, eVar6.K, 0);
                                eVar.g(eVar.M, eVar6.M, 0);
                            }
                            if (eVar != eVar7) {
                                eVar.g(eVar.L, eVar7.L, 0);
                                eVar.g(eVar.N, eVar7.N, 0);
                            }
                        }
                    }
                }
            }
        } else if (arrayList.size() > 0) {
            ((g) arrayList.get(0)).b(0, z2, true);
        }
        this.B0 = false;
    }
}

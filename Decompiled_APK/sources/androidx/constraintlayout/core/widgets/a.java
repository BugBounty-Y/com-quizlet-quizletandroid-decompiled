package androidx.constraintlayout.core.widgets;

import androidx.compose.animation.d0;

/* loaded from: classes.dex */
public final class a extends j {
    public int v0 = 0;
    public boolean w0 = true;
    public int x0 = 0;
    public boolean y0 = false;

    @Override // androidx.constraintlayout.core.widgets.e
    public final boolean B() {
        return this.y0;
    }

    @Override // androidx.constraintlayout.core.widgets.e
    public final boolean C() {
        return this.y0;
    }

    public final boolean Y() {
        int i;
        int i2;
        int i3;
        boolean z = true;
        int i4 = 0;
        while (true) {
            i = this.u0;
            if (i4 >= i) {
                break;
            }
            e eVar = this.t0[i4];
            if ((this.w0 || eVar.d()) && ((((i2 = this.v0) == 0 || i2 == 1) && !eVar.B()) || (((i3 = this.v0) == 2 || i3 == 3) && !eVar.C()))) {
                z = false;
            }
            i4++;
        }
        if (!z || i <= 0) {
            return false;
        }
        int iMax = 0;
        boolean z2 = false;
        for (int i5 = 0; i5 < this.u0; i5++) {
            e eVar2 = this.t0[i5];
            if (this.w0 || eVar2.d()) {
                if (!z2) {
                    int i6 = this.v0;
                    if (i6 == 0) {
                        iMax = eVar2.j(2).d();
                    } else if (i6 == 1) {
                        iMax = eVar2.j(4).d();
                    } else if (i6 == 2) {
                        iMax = eVar2.j(3).d();
                    } else if (i6 == 3) {
                        iMax = eVar2.j(5).d();
                    }
                    z2 = true;
                }
                int i7 = this.v0;
                if (i7 == 0) {
                    iMax = Math.min(iMax, eVar2.j(2).d());
                } else if (i7 == 1) {
                    iMax = Math.max(iMax, eVar2.j(4).d());
                } else if (i7 == 2) {
                    iMax = Math.min(iMax, eVar2.j(3).d());
                } else if (i7 == 3) {
                    iMax = Math.max(iMax, eVar2.j(5).d());
                }
            }
        }
        int i8 = iMax + this.x0;
        int i9 = this.v0;
        if (i9 == 0 || i9 == 1) {
            L(i8, i8);
        } else {
            M(i8, i8);
        }
        this.y0 = true;
        return true;
    }

    public final int Z() {
        int i = this.v0;
        if (i == 0 || i == 1) {
            return 0;
        }
        return (i == 2 || i == 3) ? 1 : -1;
    }

    @Override // androidx.constraintlayout.core.widgets.e
    public final void c(androidx.constraintlayout.core.c cVar, boolean z) {
        boolean z2;
        int i;
        c[] cVarArr = this.S;
        c cVar2 = this.K;
        cVarArr[0] = cVar2;
        c cVar3 = this.L;
        int i2 = 2;
        cVarArr[2] = cVar3;
        c cVar4 = this.M;
        cVarArr[1] = cVar4;
        c cVar5 = this.N;
        cVarArr[3] = cVar5;
        for (c cVar6 : cVarArr) {
            cVar6.i = cVar.k(cVar6);
        }
        int i3 = this.v0;
        if (i3 < 0 || i3 >= 4) {
            return;
        }
        c cVar7 = cVarArr[i3];
        if (!this.y0) {
            Y();
        }
        if (this.y0) {
            this.y0 = false;
            int i4 = this.v0;
            if (i4 == 0 || i4 == 1) {
                cVar.d(cVar2.i, this.b0);
                cVar.d(cVar4.i, this.b0);
                return;
            } else {
                if (i4 == 2 || i4 == 3) {
                    cVar.d(cVar3.i, this.c0);
                    cVar.d(cVar5.i, this.c0);
                    return;
                }
                return;
            }
        }
        for (int i5 = 0; i5 < this.u0; i5++) {
            e eVar = this.t0[i5];
            if (this.w0 || eVar.d()) {
                int i6 = this.v0;
                d dVar = d.c;
                if (((i6 == 0 || i6 == 1) && eVar.V[0] == dVar && eVar.K.f != null && eVar.M.f != null) || ((i6 == 2 || i6 == 3) && eVar.V[1] == dVar && eVar.L.f != null && eVar.N.f != null)) {
                    z2 = true;
                    break;
                }
            }
        }
        z2 = false;
        boolean z3 = cVar2.g() || cVar4.g();
        boolean z4 = cVar3.g() || cVar5.g();
        int i7 = (z2 || !(((i = this.v0) == 0 && z3) || ((i == 2 && z4) || ((i == 1 && z3) || (i == 3 && z4))))) ? 4 : 5;
        int i8 = 0;
        while (i8 < this.u0) {
            e eVar2 = this.t0[i8];
            if (this.w0 || eVar2.d()) {
                androidx.constraintlayout.core.g gVarK = cVar.k(eVar2.S[this.v0]);
                int i9 = this.v0;
                c cVar8 = eVar2.S[i9];
                cVar8.i = gVarK;
                c cVar9 = cVar8.f;
                int i10 = (cVar9 == null || cVar9.d != this) ? 0 : cVar8.g;
                if (i9 == 0 || i9 == i2) {
                    androidx.constraintlayout.core.g gVar = cVar7.i;
                    int i11 = this.x0 - i10;
                    androidx.constraintlayout.core.b bVarL = cVar.l();
                    androidx.constraintlayout.core.g gVarM = cVar.m();
                    gVarM.d = 0;
                    bVarL.c(gVar, gVarK, gVarM, i11);
                    cVar.c(bVarL);
                } else {
                    androidx.constraintlayout.core.g gVar2 = cVar7.i;
                    int i12 = this.x0 + i10;
                    androidx.constraintlayout.core.b bVarL2 = cVar.l();
                    androidx.constraintlayout.core.g gVarM2 = cVar.m();
                    gVarM2.d = 0;
                    bVarL2.b(gVar2, gVarK, gVarM2, i12);
                    cVar.c(bVarL2);
                }
                cVar.e(cVar7.i, gVarK, this.x0 + i10, i7);
            }
            i8++;
            i2 = 2;
        }
        int i13 = this.v0;
        if (i13 == 0) {
            cVar.e(cVar4.i, cVar2.i, 0, 8);
            cVar.e(cVar2.i, this.W.M.i, 0, 4);
            cVar.e(cVar2.i, this.W.K.i, 0, 0);
            return;
        }
        if (i13 == 1) {
            cVar.e(cVar2.i, cVar4.i, 0, 8);
            cVar.e(cVar2.i, this.W.K.i, 0, 4);
            cVar.e(cVar2.i, this.W.M.i, 0, 0);
        } else if (i13 == 2) {
            cVar.e(cVar5.i, cVar3.i, 0, 8);
            cVar.e(cVar3.i, this.W.N.i, 0, 4);
            cVar.e(cVar3.i, this.W.L.i, 0, 0);
        } else if (i13 == 3) {
            cVar.e(cVar3.i, cVar5.i, 0, 8);
            cVar.e(cVar3.i, this.W.L.i, 0, 4);
            cVar.e(cVar3.i, this.W.N.i, 0, 0);
        }
    }

    @Override // androidx.constraintlayout.core.widgets.e
    public final boolean d() {
        return true;
    }

    @Override // androidx.constraintlayout.core.widgets.e
    public final String toString() {
        String strT = android.support.v4.media.session.a.t(new StringBuilder("[Barrier] "), this.l0, " {");
        for (int i = 0; i < this.u0; i++) {
            e eVar = this.t0[i];
            if (i > 0) {
                strT = android.support.v4.media.session.a.k(strT, ", ");
            }
            StringBuilder sbU = d0.u(strT);
            sbU.append(eVar.l0);
            strT = sbU.toString();
        }
        return android.support.v4.media.session.a.k(strT, "}");
    }
}

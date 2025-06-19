package androidx.constraintlayout.core.widgets;

/* loaded from: classes.dex */
public final class g {
    public int a;
    public c d;
    public c e;
    public c f;
    public c g;
    public int h;
    public int i;
    public int j;
    public int k;
    public int q;
    public final /* synthetic */ h r;
    public e b = null;
    public int c = 0;
    public int l = 0;
    public int m = 0;
    public int n = 0;
    public int o = 0;
    public int p = 0;

    public g(h hVar, int i, c cVar, c cVar2, c cVar3, c cVar4, int i2) {
        this.r = hVar;
        this.a = i;
        this.d = cVar;
        this.e = cVar2;
        this.f = cVar3;
        this.g = cVar4;
        this.h = hVar.z0;
        this.i = hVar.v0;
        this.j = hVar.A0;
        this.k = hVar.w0;
        this.q = i2;
    }

    public final void a(e eVar) {
        int i = this.a;
        d dVar = d.c;
        h hVar = this.r;
        if (i == 0) {
            int iB0 = hVar.b0(eVar, this.q);
            if (eVar.V[0] == dVar) {
                this.p++;
                iB0 = 0;
            }
            this.l = iB0 + (eVar.j0 != 8 ? hVar.S0 : 0) + this.l;
            int iA0 = hVar.a0(eVar, this.q);
            if (this.b == null || this.c < iA0) {
                this.b = eVar;
                this.c = iA0;
                this.m = iA0;
            }
        } else {
            int iB02 = hVar.b0(eVar, this.q);
            int iA02 = hVar.a0(eVar, this.q);
            if (eVar.V[1] == dVar) {
                this.p++;
                iA02 = 0;
            }
            this.m = iA02 + (eVar.j0 != 8 ? hVar.T0 : 0) + this.m;
            if (this.b == null || this.c < iB02) {
                this.b = eVar;
                this.c = iB02;
                this.l = iB02;
            }
        }
        this.o++;
    }

    public final void b(int i, boolean z, boolean z2) {
        h hVar;
        int i2;
        e eVar;
        boolean z3;
        char c;
        float f;
        float f2;
        int i3;
        float f3;
        float f4;
        int i4;
        int i5 = this.o;
        int i6 = 0;
        while (true) {
            hVar = this.r;
            if (i6 >= i5 || (i4 = this.n + i6) >= hVar.e1) {
                break;
            }
            e eVar2 = hVar.d1[i4];
            if (eVar2 != null) {
                eVar2.E();
            }
            i6++;
        }
        if (i5 == 0 || this.b == null) {
            return;
        }
        boolean z4 = z2 && i == 0;
        int i7 = -1;
        int i8 = -1;
        for (int i9 = 0; i9 < i5; i9++) {
            int i10 = this.n + (z ? (i5 - 1) - i9 : i9);
            if (i10 >= hVar.e1) {
                break;
            }
            e eVar3 = hVar.d1[i10];
            if (eVar3 != null && eVar3.j0 == 0) {
                if (i7 == -1) {
                    i7 = i9;
                }
                i8 = i9;
            }
        }
        if (this.a != 0) {
            boolean z5 = z4;
            e eVar4 = this.b;
            eVar4.m0 = hVar.G0;
            int i11 = this.h;
            if (i > 0) {
                i11 += hVar.S0;
            }
            c cVar = eVar4.K;
            c cVar2 = eVar4.M;
            if (z) {
                cVar2.a(this.f, i11);
                if (z2) {
                    cVar.a(this.d, this.j);
                }
                if (i > 0) {
                    this.f.d.K.a(cVar2, 0);
                }
            } else {
                cVar.a(this.d, i11);
                if (z2) {
                    cVar2.a(this.f, this.j);
                }
                if (i > 0) {
                    this.d.d.M.a(cVar, 0);
                }
            }
            e eVar5 = null;
            for (int i12 = 0; i12 < i5; i12++) {
                int i13 = this.n + i12;
                if (i13 >= hVar.e1) {
                    return;
                }
                e eVar6 = hVar.d1[i13];
                if (eVar6 != null) {
                    c cVar3 = eVar6.L;
                    if (i12 == 0) {
                        eVar6.g(cVar3, this.e, this.i);
                        int i14 = hVar.H0;
                        float f5 = hVar.N0;
                        if (this.n == 0) {
                            int i15 = hVar.J0;
                            i2 = -1;
                            if (i15 != -1) {
                                f5 = hVar.P0;
                            }
                            i14 = i15;
                            eVar6.n0 = i14;
                            eVar6.h0 = f5;
                        } else {
                            i2 = -1;
                        }
                        if (z2 && (i15 = hVar.L0) != i2) {
                            f5 = hVar.R0;
                            i14 = i15;
                        }
                        eVar6.n0 = i14;
                        eVar6.h0 = f5;
                    }
                    if (i12 == i5 - 1) {
                        eVar6.g(eVar6.N, this.g, this.k);
                    }
                    if (eVar5 != null) {
                        int i16 = hVar.T0;
                        c cVar4 = eVar5.N;
                        cVar3.a(cVar4, i16);
                        if (i12 == i7) {
                            int i17 = this.i;
                            if (cVar3.h()) {
                                cVar3.h = i17;
                            }
                        }
                        cVar4.a(cVar3, 0);
                        if (i12 == i8 + 1) {
                            int i18 = this.k;
                            if (cVar4.h()) {
                                cVar4.h = i18;
                            }
                        }
                    }
                    if (eVar6 != eVar4) {
                        c cVar5 = eVar6.M;
                        c cVar6 = eVar6.K;
                        if (z) {
                            int i19 = hVar.U0;
                            if (i19 == 0) {
                                cVar5.a(cVar2, 0);
                            } else if (i19 == 1) {
                                cVar6.a(cVar, 0);
                            } else if (i19 == 2) {
                                cVar6.a(cVar, 0);
                                cVar5.a(cVar2, 0);
                            }
                            eVar5 = eVar6;
                        } else {
                            int i20 = hVar.U0;
                            if (i20 == 0) {
                                cVar6.a(cVar, 0);
                            } else if (i20 == 1) {
                                cVar5.a(cVar2, 0);
                            } else if (i20 == 2) {
                                if (z5) {
                                    cVar6.a(this.d, this.h);
                                    cVar5.a(this.f, this.j);
                                } else {
                                    cVar6.a(cVar, 0);
                                    cVar5.a(cVar2, 0);
                                }
                            }
                            eVar5 = eVar6;
                        }
                    } else {
                        eVar5 = eVar6;
                    }
                }
            }
            return;
        }
        e eVar7 = this.b;
        eVar7.n0 = hVar.H0;
        int i21 = this.i;
        if (i > 0) {
            i21 += hVar.T0;
        }
        c cVar7 = this.e;
        c cVar8 = eVar7.L;
        cVar8.a(cVar7, i21);
        c cVar9 = eVar7.N;
        if (z2) {
            cVar9.a(this.g, this.k);
        }
        if (i > 0) {
            this.e.d.N.a(cVar8, 0);
        }
        if (hVar.V0 != 3 || eVar7.F) {
            eVar = eVar7;
        } else {
            for (int i22 = 0; i22 < i5; i22++) {
                int i23 = this.n + (z ? (i5 - 1) - i22 : i22);
                if (i23 >= hVar.e1) {
                    break;
                }
                eVar = hVar.d1[i23];
                if (eVar.F) {
                    break;
                }
            }
            eVar = eVar7;
        }
        int i24 = 0;
        e eVar8 = null;
        while (i24 < i5) {
            int i25 = z ? (i5 - 1) - i24 : i24;
            int i26 = this.n + i25;
            if (i26 >= hVar.e1) {
                return;
            }
            e eVar9 = hVar.d1[i26];
            if (eVar9 == null) {
                z3 = z4;
                c = 3;
            } else {
                c cVar10 = eVar9.K;
                if (i24 == 0) {
                    eVar9.g(cVar10, this.d, this.h);
                }
                if (i25 == 0) {
                    int i27 = hVar.G0;
                    if (z) {
                        f = 1.0f;
                        f2 = 1.0f - hVar.M0;
                    } else {
                        f = 1.0f;
                        f2 = hVar.M0;
                    }
                    if (this.n == 0) {
                        i3 = hVar.I0;
                        z3 = z4;
                        if (i3 != -1) {
                            if (z) {
                                f4 = hVar.O0;
                                f2 = f - f4;
                            } else {
                                f3 = hVar.O0;
                                f2 = f3;
                            }
                        }
                        eVar9.m0 = i3;
                        eVar9.g0 = f2;
                    } else {
                        z3 = z4;
                    }
                    if (!z2 || (i3 = hVar.K0) == -1) {
                        i3 = i27;
                        eVar9.m0 = i3;
                        eVar9.g0 = f2;
                    } else if (z) {
                        f4 = hVar.Q0;
                        f2 = f - f4;
                        eVar9.m0 = i3;
                        eVar9.g0 = f2;
                    } else {
                        f3 = hVar.Q0;
                        f2 = f3;
                        eVar9.m0 = i3;
                        eVar9.g0 = f2;
                    }
                } else {
                    z3 = z4;
                }
                if (i24 == i5 - 1) {
                    eVar9.g(eVar9.M, this.f, this.j);
                }
                if (eVar8 != null) {
                    int i28 = hVar.S0;
                    c cVar11 = eVar8.M;
                    cVar10.a(cVar11, i28);
                    if (i24 == i7) {
                        int i29 = this.h;
                        if (cVar10.h()) {
                            cVar10.h = i29;
                        }
                    }
                    cVar11.a(cVar10, 0);
                    if (i24 == i8 + 1) {
                        int i30 = this.j;
                        if (cVar11.h()) {
                            cVar11.h = i30;
                        }
                    }
                }
                if (eVar9 != eVar7) {
                    int i31 = hVar.V0;
                    c = 3;
                    if (i31 == 3 && eVar.F && eVar9 != eVar && eVar9.F) {
                        eVar9.O.a(eVar.O, 0);
                    } else {
                        c cVar12 = eVar9.L;
                        if (i31 != 0) {
                            c cVar13 = eVar9.N;
                            if (i31 == 1) {
                                cVar13.a(cVar9, 0);
                            } else if (z3) {
                                cVar12.a(this.e, this.i);
                                cVar13.a(this.g, this.k);
                            } else {
                                cVar12.a(cVar8, 0);
                                cVar13.a(cVar9, 0);
                            }
                        } else {
                            cVar12.a(cVar8, 0);
                        }
                    }
                } else {
                    c = 3;
                }
                eVar8 = eVar9;
            }
            i24++;
            z4 = z3;
        }
    }

    public final int c() {
        return this.a == 1 ? this.m - this.r.T0 : this.m;
    }

    public final int d() {
        return this.a == 0 ? this.l - this.r.S0 : this.l;
    }

    public final void e(int i) {
        int i2 = this.p;
        if (i2 == 0) {
            return;
        }
        int i3 = this.o;
        int i4 = i / i2;
        for (int i5 = 0; i5 < i3; i5++) {
            int i6 = this.n;
            int i7 = i6 + i5;
            h hVar = this.r;
            if (i7 >= hVar.e1) {
                break;
            }
            e eVar = hVar.d1[i6 + i5];
            int i8 = this.a;
            d dVar = d.a;
            d dVar2 = d.c;
            if (i8 == 0) {
                if (eVar != null) {
                    d[] dVarArr = eVar.V;
                    if (dVarArr[0] == dVar2 && eVar.s == 0) {
                        hVar.Z(eVar, dVar, i4, dVarArr[1], eVar.l());
                    }
                }
            } else if (eVar != null) {
                d[] dVarArr2 = eVar.V;
                if (dVarArr2[1] == dVar2 && eVar.t == 0) {
                    int i9 = i4;
                    hVar.Z(eVar, dVarArr2[0], eVar.r(), dVar, i9);
                    i4 = i9;
                }
            }
        }
        this.l = 0;
        this.m = 0;
        this.b = null;
        this.c = 0;
        int i10 = this.o;
        for (int i11 = 0; i11 < i10; i11++) {
            int i12 = this.n + i11;
            h hVar2 = this.r;
            if (i12 >= hVar2.e1) {
                return;
            }
            e eVar2 = hVar2.d1[i12];
            if (this.a == 0) {
                int iR = eVar2.r();
                int i13 = hVar2.S0;
                if (eVar2.j0 == 8) {
                    i13 = 0;
                }
                this.l = iR + i13 + this.l;
                int iA0 = hVar2.a0(eVar2, this.q);
                if (this.b == null || this.c < iA0) {
                    this.b = eVar2;
                    this.c = iA0;
                    this.m = iA0;
                }
            } else {
                int iB0 = hVar2.b0(eVar2, this.q);
                int iA02 = hVar2.a0(eVar2, this.q);
                int i14 = hVar2.T0;
                if (eVar2.j0 == 8) {
                    i14 = 0;
                }
                this.m = iA02 + i14 + this.m;
                if (this.b == null || this.c < iB0) {
                    this.b = eVar2;
                    this.c = iB0;
                    this.l = iB0;
                }
            }
        }
    }

    public final void f(int i, c cVar, c cVar2, c cVar3, c cVar4, int i2, int i3, int i4, int i5, int i6) {
        this.a = i;
        this.d = cVar;
        this.e = cVar2;
        this.f = cVar3;
        this.g = cVar4;
        this.h = i2;
        this.i = i3;
        this.j = i4;
        this.k = i5;
        this.q = i6;
    }
}

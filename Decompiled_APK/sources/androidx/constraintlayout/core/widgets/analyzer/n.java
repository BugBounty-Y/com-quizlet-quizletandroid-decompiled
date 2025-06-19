package androidx.constraintlayout.core.widgets.analyzer;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class n extends p {
    public g k;
    public a l;

    @Override // androidx.constraintlayout.core.widgets.analyzer.e
    public final void a(e eVar) {
        float f;
        float f2;
        float f3;
        int i;
        if (AbstractC0147y.k(this.j) == 3) {
            androidx.constraintlayout.core.widgets.e eVar2 = this.b;
            l(eVar2.L, eVar2.N, 1);
            return;
        }
        h hVar = this.e;
        boolean z = hVar.c;
        androidx.constraintlayout.core.widgets.d dVar = androidx.constraintlayout.core.widgets.d.c;
        if (z && !hVar.j && this.d == dVar) {
            androidx.constraintlayout.core.widgets.e eVar3 = this.b;
            int i2 = eVar3.t;
            if (i2 == 2) {
                androidx.constraintlayout.core.widgets.e eVar4 = eVar3.W;
                if (eVar4 != null) {
                    if (eVar4.e.e.j) {
                        hVar.d((int) ((r1.g * eVar3.A) + 0.5f));
                    }
                }
            } else if (i2 == 3) {
                h hVar2 = eVar3.d.e;
                if (hVar2.j) {
                    int i3 = eVar3.a0;
                    if (i3 == -1) {
                        f = hVar2.g;
                        f2 = eVar3.Z;
                    } else if (i3 == 0) {
                        f3 = hVar2.g * eVar3.Z;
                        i = (int) (f3 + 0.5f);
                        hVar.d(i);
                    } else if (i3 != 1) {
                        i = 0;
                        hVar.d(i);
                    } else {
                        f = hVar2.g;
                        f2 = eVar3.Z;
                    }
                    f3 = f / f2;
                    i = (int) (f3 + 0.5f);
                    hVar.d(i);
                }
            }
        }
        g gVar = this.h;
        if (gVar.c) {
            g gVar2 = this.i;
            if (gVar2.c) {
                if (gVar.j && gVar2.j && hVar.j) {
                    return;
                }
                if (!hVar.j && this.d == dVar) {
                    androidx.constraintlayout.core.widgets.e eVar5 = this.b;
                    if (eVar5.s == 0 && !eVar5.z()) {
                        g gVar3 = (g) gVar.l.get(0);
                        g gVar4 = (g) gVar2.l.get(0);
                        int i4 = gVar3.g + gVar.f;
                        int i5 = gVar4.g + gVar2.f;
                        gVar.d(i4);
                        gVar2.d(i5);
                        hVar.d(i5 - i4);
                        return;
                    }
                }
                if (!hVar.j && this.d == dVar && this.a == 1 && gVar.l.size() > 0 && gVar2.l.size() > 0) {
                    g gVar5 = (g) gVar.l.get(0);
                    int i6 = (((g) gVar2.l.get(0)).g + gVar2.f) - (gVar5.g + gVar.f);
                    int i7 = hVar.m;
                    if (i6 < i7) {
                        hVar.d(i6);
                    } else {
                        hVar.d(i7);
                    }
                }
                if (hVar.j && gVar.l.size() > 0 && gVar2.l.size() > 0) {
                    g gVar6 = (g) gVar.l.get(0);
                    g gVar7 = (g) gVar2.l.get(0);
                    int i8 = gVar6.g;
                    int i9 = gVar.f + i8;
                    int i10 = gVar7.g;
                    int i11 = gVar2.f + i10;
                    float f4 = this.b.h0;
                    if (gVar6 == gVar7) {
                        f4 = 0.5f;
                    } else {
                        i8 = i9;
                        i10 = i11;
                    }
                    gVar.d((int) ((((i10 - i8) - hVar.g) * f4) + i8 + 0.5f));
                    gVar2.d(gVar.g + hVar.g);
                }
            }
        }
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.p
    public final void d() {
        androidx.constraintlayout.core.widgets.e eVar;
        androidx.constraintlayout.core.widgets.e eVar2;
        androidx.constraintlayout.core.widgets.e eVar3;
        androidx.constraintlayout.core.widgets.e eVar4;
        androidx.constraintlayout.core.widgets.e eVar5 = this.b;
        boolean z = eVar5.a;
        h hVar = this.e;
        if (z) {
            hVar.d(eVar5.l());
        }
        boolean z2 = hVar.j;
        androidx.constraintlayout.core.widgets.d dVar = androidx.constraintlayout.core.widgets.d.d;
        androidx.constraintlayout.core.widgets.d dVar2 = androidx.constraintlayout.core.widgets.d.a;
        androidx.constraintlayout.core.widgets.d dVar3 = androidx.constraintlayout.core.widgets.d.c;
        g gVar = this.i;
        g gVar2 = this.h;
        if (!z2) {
            androidx.constraintlayout.core.widgets.e eVar6 = this.b;
            this.d = eVar6.V[1];
            if (eVar6.F) {
                this.l = new a(this);
            }
            androidx.constraintlayout.core.widgets.d dVar4 = this.d;
            if (dVar4 != dVar3) {
                if (dVar4 == dVar && (eVar4 = this.b.W) != null && eVar4.V[1] == dVar2) {
                    int iL = (eVar4.l() - this.b.L.e()) - this.b.N.e();
                    p.b(gVar2, eVar4.e.h, this.b.L.e());
                    p.b(gVar, eVar4.e.i, -this.b.N.e());
                    hVar.d(iL);
                    return;
                }
                if (dVar4 == dVar2) {
                    hVar.d(this.b.l());
                }
            }
        } else if (this.d == dVar && (eVar2 = (eVar = this.b).W) != null && eVar2.V[1] == dVar2) {
            p.b(gVar2, eVar2.e.h, eVar.L.e());
            p.b(gVar, eVar2.e.i, -this.b.N.e());
            return;
        }
        boolean z3 = hVar.j;
        g gVar3 = this.k;
        if (z3) {
            androidx.constraintlayout.core.widgets.e eVar7 = this.b;
            if (eVar7.a) {
                androidx.constraintlayout.core.widgets.c[] cVarArr = eVar7.S;
                androidx.constraintlayout.core.widgets.c cVar = cVarArr[2];
                androidx.constraintlayout.core.widgets.c cVar2 = cVar.f;
                if (cVar2 != null && cVarArr[3].f != null) {
                    if (eVar7.z()) {
                        gVar2.f = this.b.S[2].e();
                        gVar.f = -this.b.S[3].e();
                    } else {
                        g gVarH = p.h(this.b.S[2]);
                        if (gVarH != null) {
                            p.b(gVar2, gVarH, this.b.S[2].e());
                        }
                        g gVarH2 = p.h(this.b.S[3]);
                        if (gVarH2 != null) {
                            p.b(gVar, gVarH2, -this.b.S[3].e());
                        }
                        gVar2.b = true;
                        gVar.b = true;
                    }
                    androidx.constraintlayout.core.widgets.e eVar8 = this.b;
                    if (eVar8.F) {
                        p.b(gVar3, gVar2, eVar8.d0);
                        return;
                    }
                    return;
                }
                if (cVar2 != null) {
                    g gVarH3 = p.h(cVar);
                    if (gVarH3 != null) {
                        p.b(gVar2, gVarH3, this.b.S[2].e());
                        p.b(gVar, gVar2, hVar.g);
                        androidx.constraintlayout.core.widgets.e eVar9 = this.b;
                        if (eVar9.F) {
                            p.b(gVar3, gVar2, eVar9.d0);
                            return;
                        }
                        return;
                    }
                    return;
                }
                androidx.constraintlayout.core.widgets.c cVar3 = cVarArr[3];
                if (cVar3.f != null) {
                    g gVarH4 = p.h(cVar3);
                    if (gVarH4 != null) {
                        p.b(gVar, gVarH4, -this.b.S[3].e());
                        p.b(gVar2, gVar, -hVar.g);
                    }
                    androidx.constraintlayout.core.widgets.e eVar10 = this.b;
                    if (eVar10.F) {
                        p.b(gVar3, gVar2, eVar10.d0);
                        return;
                    }
                    return;
                }
                androidx.constraintlayout.core.widgets.c cVar4 = cVarArr[4];
                if (cVar4.f != null) {
                    g gVarH5 = p.h(cVar4);
                    if (gVarH5 != null) {
                        p.b(gVar3, gVarH5, 0);
                        p.b(gVar2, gVar3, -this.b.d0);
                        p.b(gVar, gVar2, hVar.g);
                        return;
                    }
                    return;
                }
                if ((eVar7 instanceof androidx.constraintlayout.core.widgets.j) || eVar7.W == null || eVar7.j(7).f != null) {
                    return;
                }
                androidx.constraintlayout.core.widgets.e eVar11 = this.b;
                p.b(gVar2, eVar11.W.e.h, eVar11.t());
                p.b(gVar, gVar2, hVar.g);
                androidx.constraintlayout.core.widgets.e eVar12 = this.b;
                if (eVar12.F) {
                    p.b(gVar3, gVar2, eVar12.d0);
                    return;
                }
                return;
            }
        }
        if (z3 || this.d != dVar3) {
            hVar.b(this);
        } else {
            androidx.constraintlayout.core.widgets.e eVar13 = this.b;
            int i = eVar13.t;
            if (i == 2) {
                androidx.constraintlayout.core.widgets.e eVar14 = eVar13.W;
                if (eVar14 != null) {
                    h hVar2 = eVar14.e.e;
                    hVar.l.add(hVar2);
                    hVar2.k.add(hVar);
                    hVar.b = true;
                    hVar.k.add(gVar2);
                    hVar.k.add(gVar);
                }
            } else if (i == 3 && !eVar13.z()) {
                androidx.constraintlayout.core.widgets.e eVar15 = this.b;
                if (eVar15.s != 3) {
                    h hVar3 = eVar15.d.e;
                    hVar.l.add(hVar3);
                    hVar3.k.add(hVar);
                    hVar.b = true;
                    hVar.k.add(gVar2);
                    hVar.k.add(gVar);
                }
            }
        }
        androidx.constraintlayout.core.widgets.e eVar16 = this.b;
        androidx.constraintlayout.core.widgets.c[] cVarArr2 = eVar16.S;
        androidx.constraintlayout.core.widgets.c cVar5 = cVarArr2[2];
        androidx.constraintlayout.core.widgets.c cVar6 = cVar5.f;
        if (cVar6 != null && cVarArr2[3].f != null) {
            if (eVar16.z()) {
                gVar2.f = this.b.S[2].e();
                gVar.f = -this.b.S[3].e();
            } else {
                g gVarH6 = p.h(this.b.S[2]);
                g gVarH7 = p.h(this.b.S[3]);
                if (gVarH6 != null) {
                    gVarH6.b(this);
                }
                if (gVarH7 != null) {
                    gVarH7.b(this);
                }
                this.j = 4;
            }
            if (this.b.F) {
                c(gVar3, gVar2, 1, this.l);
            }
        } else if (cVar6 != null) {
            g gVarH8 = p.h(cVar5);
            if (gVarH8 != null) {
                p.b(gVar2, gVarH8, this.b.S[2].e());
                c(gVar, gVar2, 1, hVar);
                if (this.b.F) {
                    c(gVar3, gVar2, 1, this.l);
                }
                if (this.d == dVar3) {
                    androidx.constraintlayout.core.widgets.e eVar17 = this.b;
                    if (eVar17.Z > DefinitionKt.NO_Float_VALUE) {
                        l lVar = eVar17.d;
                        if (lVar.d == dVar3) {
                            lVar.e.k.add(hVar);
                            hVar.l.add(this.b.d.e);
                            hVar.a = this;
                        }
                    }
                }
            }
        } else {
            androidx.constraintlayout.core.widgets.c cVar7 = cVarArr2[3];
            if (cVar7.f != null) {
                g gVarH9 = p.h(cVar7);
                if (gVarH9 != null) {
                    p.b(gVar, gVarH9, -this.b.S[3].e());
                    c(gVar2, gVar, -1, hVar);
                    if (this.b.F) {
                        c(gVar3, gVar2, 1, this.l);
                    }
                }
            } else {
                androidx.constraintlayout.core.widgets.c cVar8 = cVarArr2[4];
                if (cVar8.f != null) {
                    g gVarH10 = p.h(cVar8);
                    if (gVarH10 != null) {
                        p.b(gVar3, gVarH10, 0);
                        c(gVar2, gVar3, -1, this.l);
                        c(gVar, gVar2, 1, hVar);
                    }
                } else if (!(eVar16 instanceof androidx.constraintlayout.core.widgets.j) && (eVar3 = eVar16.W) != null) {
                    p.b(gVar2, eVar3.e.h, eVar16.t());
                    c(gVar, gVar2, 1, hVar);
                    if (this.b.F) {
                        c(gVar3, gVar2, 1, this.l);
                    }
                    if (this.d == dVar3) {
                        androidx.constraintlayout.core.widgets.e eVar18 = this.b;
                        if (eVar18.Z > DefinitionKt.NO_Float_VALUE) {
                            l lVar2 = eVar18.d;
                            if (lVar2.d == dVar3) {
                                lVar2.e.k.add(hVar);
                                hVar.l.add(this.b.d.e);
                                hVar.a = this;
                            }
                        }
                    }
                }
            }
        }
        if (hVar.l.size() == 0) {
            hVar.c = true;
        }
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.p
    public final void e() {
        g gVar = this.h;
        if (gVar.j) {
            this.b.c0 = gVar.g;
        }
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.p
    public final void f() {
        this.c = null;
        this.h.c();
        this.i.c();
        this.k.c();
        this.e.c();
        this.g = false;
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.p
    public final boolean k() {
        return this.d != androidx.constraintlayout.core.widgets.d.c || this.b.t == 0;
    }

    public final void m() {
        this.g = false;
        g gVar = this.h;
        gVar.c();
        gVar.j = false;
        g gVar2 = this.i;
        gVar2.c();
        gVar2.j = false;
        g gVar3 = this.k;
        gVar3.c();
        gVar3.j = false;
        this.e.j = false;
    }

    public final String toString() {
        return "VerticalRun " + this.b.l0;
    }
}

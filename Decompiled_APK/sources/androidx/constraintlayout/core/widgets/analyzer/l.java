package androidx.constraintlayout.core.widgets.analyzer;

/* loaded from: classes.dex */
public final class l extends p {
    public static final int[] k = new int[2];

    public static void m(int[] iArr, int i, int i2, int i3, int i4, float f, int i5) {
        int i6 = i2 - i;
        int i7 = i4 - i3;
        if (i5 != -1) {
            if (i5 == 0) {
                iArr[0] = (int) ((i7 * f) + 0.5f);
                iArr[1] = i7;
                return;
            } else {
                if (i5 != 1) {
                    return;
                }
                iArr[0] = i6;
                iArr[1] = (int) ((i6 * f) + 0.5f);
                return;
            }
        }
        int i8 = (int) ((i7 * f) + 0.5f);
        int i9 = (int) ((i6 / f) + 0.5f);
        if (i8 <= i6) {
            iArr[0] = i8;
            iArr[1] = i7;
        } else if (i9 <= i7) {
            iArr[0] = i6;
            iArr[1] = i9;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:116:0x026a  */
    /* JADX WARN: Removed duplicated region for block: B:11:0x0028  */
    @Override // androidx.constraintlayout.core.widgets.analyzer.e
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a(androidx.constraintlayout.core.widgets.analyzer.e r24) {
        /*
            Method dump skipped, instructions count: 915
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.widgets.analyzer.l.a(androidx.constraintlayout.core.widgets.analyzer.e):void");
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.p
    public final void d() {
        androidx.constraintlayout.core.widgets.e eVar;
        androidx.constraintlayout.core.widgets.e eVar2;
        androidx.constraintlayout.core.widgets.d dVar;
        androidx.constraintlayout.core.widgets.e eVar3;
        androidx.constraintlayout.core.widgets.e eVar4;
        androidx.constraintlayout.core.widgets.d dVar2;
        androidx.constraintlayout.core.widgets.e eVar5 = this.b;
        boolean z = eVar5.a;
        h hVar = this.e;
        if (z) {
            hVar.d(eVar5.r());
        }
        boolean z2 = hVar.j;
        androidx.constraintlayout.core.widgets.d dVar3 = androidx.constraintlayout.core.widgets.d.d;
        androidx.constraintlayout.core.widgets.d dVar4 = androidx.constraintlayout.core.widgets.d.c;
        androidx.constraintlayout.core.widgets.d dVar5 = androidx.constraintlayout.core.widgets.d.a;
        g gVar = this.i;
        g gVar2 = this.h;
        if (!z2) {
            androidx.constraintlayout.core.widgets.e eVar6 = this.b;
            androidx.constraintlayout.core.widgets.d dVar6 = eVar6.V[0];
            this.d = dVar6;
            if (dVar6 != dVar4) {
                if (dVar6 == dVar3 && (eVar4 = eVar6.W) != null && ((dVar2 = eVar4.V[0]) == dVar5 || dVar2 == dVar3)) {
                    int iR = (eVar4.r() - this.b.K.e()) - this.b.M.e();
                    p.b(gVar2, eVar4.d.h, this.b.K.e());
                    p.b(gVar, eVar4.d.i, -this.b.M.e());
                    hVar.d(iR);
                    return;
                }
                if (dVar6 == dVar5) {
                    hVar.d(eVar6.r());
                }
            }
        } else if (this.d == dVar3 && (eVar2 = (eVar = this.b).W) != null && ((dVar = eVar2.V[0]) == dVar5 || dVar == dVar3)) {
            p.b(gVar2, eVar2.d.h, eVar.K.e());
            p.b(gVar, eVar2.d.i, -this.b.M.e());
            return;
        }
        if (hVar.j) {
            androidx.constraintlayout.core.widgets.e eVar7 = this.b;
            if (eVar7.a) {
                androidx.constraintlayout.core.widgets.c[] cVarArr = eVar7.S;
                androidx.constraintlayout.core.widgets.c cVar = cVarArr[0];
                androidx.constraintlayout.core.widgets.c cVar2 = cVar.f;
                if (cVar2 != null && cVarArr[1].f != null) {
                    if (eVar7.y()) {
                        gVar2.f = this.b.S[0].e();
                        gVar.f = -this.b.S[1].e();
                        return;
                    }
                    g gVarH = p.h(this.b.S[0]);
                    if (gVarH != null) {
                        p.b(gVar2, gVarH, this.b.S[0].e());
                    }
                    g gVarH2 = p.h(this.b.S[1]);
                    if (gVarH2 != null) {
                        p.b(gVar, gVarH2, -this.b.S[1].e());
                    }
                    gVar2.b = true;
                    gVar.b = true;
                    return;
                }
                if (cVar2 != null) {
                    g gVarH3 = p.h(cVar);
                    if (gVarH3 != null) {
                        p.b(gVar2, gVarH3, this.b.S[0].e());
                        p.b(gVar, gVar2, hVar.g);
                        return;
                    }
                    return;
                }
                androidx.constraintlayout.core.widgets.c cVar3 = cVarArr[1];
                if (cVar3.f != null) {
                    g gVarH4 = p.h(cVar3);
                    if (gVarH4 != null) {
                        p.b(gVar, gVarH4, -this.b.S[1].e());
                        p.b(gVar2, gVar, -hVar.g);
                        return;
                    }
                    return;
                }
                if ((eVar7 instanceof androidx.constraintlayout.core.widgets.j) || eVar7.W == null || eVar7.j(7).f != null) {
                    return;
                }
                androidx.constraintlayout.core.widgets.e eVar8 = this.b;
                p.b(gVar2, eVar8.W.d.h, eVar8.s());
                p.b(gVar, gVar2, hVar.g);
                return;
            }
        }
        if (this.d == dVar4) {
            androidx.constraintlayout.core.widgets.e eVar9 = this.b;
            int i = eVar9.s;
            if (i == 2) {
                androidx.constraintlayout.core.widgets.e eVar10 = eVar9.W;
                if (eVar10 != null) {
                    h hVar2 = eVar10.e.e;
                    hVar.l.add(hVar2);
                    hVar2.k.add(hVar);
                    hVar.b = true;
                    hVar.k.add(gVar2);
                    hVar.k.add(gVar);
                }
            } else if (i == 3) {
                if (eVar9.t == 3) {
                    gVar2.a = this;
                    gVar.a = this;
                    n nVar = eVar9.e;
                    nVar.h.a = this;
                    nVar.i.a = this;
                    hVar.a = this;
                    if (eVar9.z()) {
                        hVar.l.add(this.b.e.e);
                        this.b.e.e.k.add(hVar);
                        n nVar2 = this.b.e;
                        nVar2.e.a = this;
                        hVar.l.add(nVar2.h);
                        hVar.l.add(this.b.e.i);
                        this.b.e.h.k.add(hVar);
                        this.b.e.i.k.add(hVar);
                    } else if (this.b.y()) {
                        this.b.e.e.l.add(hVar);
                        hVar.k.add(this.b.e.e);
                    } else {
                        this.b.e.e.l.add(hVar);
                    }
                } else {
                    h hVar3 = eVar9.e.e;
                    hVar.l.add(hVar3);
                    hVar3.k.add(hVar);
                    this.b.e.h.k.add(hVar);
                    this.b.e.i.k.add(hVar);
                    hVar.b = true;
                    hVar.k.add(gVar2);
                    hVar.k.add(gVar);
                    gVar2.l.add(hVar);
                    gVar.l.add(hVar);
                }
            }
        }
        androidx.constraintlayout.core.widgets.e eVar11 = this.b;
        androidx.constraintlayout.core.widgets.c[] cVarArr2 = eVar11.S;
        androidx.constraintlayout.core.widgets.c cVar4 = cVarArr2[0];
        androidx.constraintlayout.core.widgets.c cVar5 = cVar4.f;
        if (cVar5 != null && cVarArr2[1].f != null) {
            if (eVar11.y()) {
                gVar2.f = this.b.S[0].e();
                gVar.f = -this.b.S[1].e();
                return;
            }
            g gVarH5 = p.h(this.b.S[0]);
            g gVarH6 = p.h(this.b.S[1]);
            if (gVarH5 != null) {
                gVarH5.b(this);
            }
            if (gVarH6 != null) {
                gVarH6.b(this);
            }
            this.j = 4;
            return;
        }
        if (cVar5 != null) {
            g gVarH7 = p.h(cVar4);
            if (gVarH7 != null) {
                p.b(gVar2, gVarH7, this.b.S[0].e());
                c(gVar, gVar2, 1, hVar);
                return;
            }
            return;
        }
        androidx.constraintlayout.core.widgets.c cVar6 = cVarArr2[1];
        if (cVar6.f != null) {
            g gVarH8 = p.h(cVar6);
            if (gVarH8 != null) {
                p.b(gVar, gVarH8, -this.b.S[1].e());
                c(gVar2, gVar, -1, hVar);
                return;
            }
            return;
        }
        if ((eVar11 instanceof androidx.constraintlayout.core.widgets.j) || (eVar3 = eVar11.W) == null) {
            return;
        }
        p.b(gVar2, eVar3.d.h, eVar11.s());
        c(gVar, gVar2, 1, hVar);
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.p
    public final void e() {
        g gVar = this.h;
        if (gVar.j) {
            this.b.b0 = gVar.g;
        }
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.p
    public final void f() {
        this.c = null;
        this.h.c();
        this.i.c();
        this.e.c();
        this.g = false;
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.p
    public final boolean k() {
        return this.d != androidx.constraintlayout.core.widgets.d.c || this.b.s == 0;
    }

    public final void n() {
        this.g = false;
        g gVar = this.h;
        gVar.c();
        gVar.j = false;
        g gVar2 = this.i;
        gVar2.c();
        gVar2.j = false;
        this.e.j = false;
    }

    public final String toString() {
        return "HorizontalRun " + this.b.l0;
    }
}

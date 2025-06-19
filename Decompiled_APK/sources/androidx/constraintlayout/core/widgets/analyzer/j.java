package androidx.constraintlayout.core.widgets.analyzer;

/* loaded from: classes.dex */
public final class j extends p {
    @Override // androidx.constraintlayout.core.widgets.analyzer.e
    public final void a(e eVar) {
        g gVar = this.h;
        if (gVar.c && !gVar.j) {
            gVar.d((int) ((((g) gVar.l.get(0)).g * ((androidx.constraintlayout.core.widgets.i) this.b).t0) + 0.5f));
        }
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.p
    public final void d() {
        androidx.constraintlayout.core.widgets.e eVar = this.b;
        androidx.constraintlayout.core.widgets.i iVar = (androidx.constraintlayout.core.widgets.i) eVar;
        int i = iVar.u0;
        int i2 = iVar.v0;
        int i3 = iVar.x0;
        g gVar = this.h;
        if (i3 == 1) {
            if (i != -1) {
                gVar.l.add(eVar.W.d.h);
                this.b.W.d.h.k.add(gVar);
                gVar.f = i;
            } else if (i2 != -1) {
                gVar.l.add(eVar.W.d.i);
                this.b.W.d.i.k.add(gVar);
                gVar.f = -i2;
            } else {
                gVar.b = true;
                gVar.l.add(eVar.W.d.i);
                this.b.W.d.i.k.add(gVar);
            }
            m(this.b.d.h);
            m(this.b.d.i);
            return;
        }
        if (i != -1) {
            gVar.l.add(eVar.W.e.h);
            this.b.W.e.h.k.add(gVar);
            gVar.f = i;
        } else if (i2 != -1) {
            gVar.l.add(eVar.W.e.i);
            this.b.W.e.i.k.add(gVar);
            gVar.f = -i2;
        } else {
            gVar.b = true;
            gVar.l.add(eVar.W.e.i);
            this.b.W.e.i.k.add(gVar);
        }
        m(this.b.e.h);
        m(this.b.e.i);
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.p
    public final void e() {
        androidx.constraintlayout.core.widgets.e eVar = this.b;
        int i = ((androidx.constraintlayout.core.widgets.i) eVar).x0;
        g gVar = this.h;
        if (i == 1) {
            eVar.b0 = gVar.g;
        } else {
            eVar.c0 = gVar.g;
        }
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.p
    public final void f() {
        this.h.c();
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.p
    public final boolean k() {
        return false;
    }

    public final void m(g gVar) {
        g gVar2 = this.h;
        gVar2.k.add(gVar);
        gVar.l.add(gVar2);
    }
}

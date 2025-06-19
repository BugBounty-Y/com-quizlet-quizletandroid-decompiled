package androidx.constraintlayout.core.widgets.analyzer;

import java.util.Iterator;

/* loaded from: classes.dex */
public final class k extends p {
    @Override // androidx.constraintlayout.core.widgets.analyzer.e
    public final void a(e eVar) {
        androidx.constraintlayout.core.widgets.a aVar = (androidx.constraintlayout.core.widgets.a) this.b;
        int i = aVar.v0;
        g gVar = this.h;
        Iterator it2 = gVar.l.iterator();
        int i2 = 0;
        int i3 = -1;
        while (it2.hasNext()) {
            int i4 = ((g) it2.next()).g;
            if (i3 == -1 || i4 < i3) {
                i3 = i4;
            }
            if (i2 < i4) {
                i2 = i4;
            }
        }
        if (i == 0 || i == 2) {
            gVar.d(i3 + aVar.x0);
        } else {
            gVar.d(i2 + aVar.x0);
        }
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.p
    public final void d() {
        androidx.constraintlayout.core.widgets.e eVar = this.b;
        if (eVar instanceof androidx.constraintlayout.core.widgets.a) {
            g gVar = this.h;
            gVar.b = true;
            androidx.constraintlayout.core.widgets.a aVar = (androidx.constraintlayout.core.widgets.a) eVar;
            int i = aVar.v0;
            boolean z = aVar.w0;
            int i2 = 0;
            if (i == 0) {
                gVar.e = 4;
                while (i2 < aVar.u0) {
                    androidx.constraintlayout.core.widgets.e eVar2 = aVar.t0[i2];
                    if (z || eVar2.j0 != 8) {
                        g gVar2 = eVar2.d.h;
                        gVar2.k.add(gVar);
                        gVar.l.add(gVar2);
                    }
                    i2++;
                }
                m(this.b.d.h);
                m(this.b.d.i);
                return;
            }
            if (i == 1) {
                gVar.e = 5;
                while (i2 < aVar.u0) {
                    androidx.constraintlayout.core.widgets.e eVar3 = aVar.t0[i2];
                    if (z || eVar3.j0 != 8) {
                        g gVar3 = eVar3.d.i;
                        gVar3.k.add(gVar);
                        gVar.l.add(gVar3);
                    }
                    i2++;
                }
                m(this.b.d.h);
                m(this.b.d.i);
                return;
            }
            if (i == 2) {
                gVar.e = 6;
                while (i2 < aVar.u0) {
                    androidx.constraintlayout.core.widgets.e eVar4 = aVar.t0[i2];
                    if (z || eVar4.j0 != 8) {
                        g gVar4 = eVar4.e.h;
                        gVar4.k.add(gVar);
                        gVar.l.add(gVar4);
                    }
                    i2++;
                }
                m(this.b.e.h);
                m(this.b.e.i);
                return;
            }
            if (i != 3) {
                return;
            }
            gVar.e = 7;
            while (i2 < aVar.u0) {
                androidx.constraintlayout.core.widgets.e eVar5 = aVar.t0[i2];
                if (z || eVar5.j0 != 8) {
                    g gVar5 = eVar5.e.i;
                    gVar5.k.add(gVar);
                    gVar.l.add(gVar5);
                }
                i2++;
            }
            m(this.b.e.h);
            m(this.b.e.i);
        }
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.p
    public final void e() {
        androidx.constraintlayout.core.widgets.e eVar = this.b;
        if (eVar instanceof androidx.constraintlayout.core.widgets.a) {
            int i = ((androidx.constraintlayout.core.widgets.a) eVar).v0;
            g gVar = this.h;
            if (i == 0 || i == 1) {
                eVar.b0 = gVar.g;
            } else {
                eVar.c0 = gVar.g;
            }
        }
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.p
    public final void f() {
        this.c = null;
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

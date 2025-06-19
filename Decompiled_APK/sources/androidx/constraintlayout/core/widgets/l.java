package androidx.constraintlayout.core.widgets;

/* loaded from: classes.dex */
public abstract class l extends j {
    public int v0 = 0;
    public int w0 = 0;
    public int x0 = 0;
    public int y0 = 0;
    public int z0 = 0;
    public int A0 = 0;
    public boolean B0 = false;
    public int C0 = 0;
    public int D0 = 0;
    public final androidx.constraintlayout.core.widgets.analyzer.b E0 = new androidx.constraintlayout.core.widgets.analyzer.b();
    public androidx.constraintlayout.core.widgets.analyzer.c F0 = null;

    @Override // androidx.constraintlayout.core.widgets.j
    public final void X() {
        for (int i = 0; i < this.u0; i++) {
            e eVar = this.t0[i];
            if (eVar != null) {
                eVar.H = true;
            }
        }
    }

    public abstract void Y(int i, int i2, int i3, int i4);

    public final void Z(e eVar, d dVar, int i, d dVar2, int i2) {
        androidx.constraintlayout.core.widgets.analyzer.c cVar;
        e eVar2;
        while (true) {
            cVar = this.F0;
            if (cVar != null || (eVar2 = this.W) == null) {
                break;
            } else {
                this.F0 = ((f) eVar2).x0;
            }
        }
        androidx.constraintlayout.core.widgets.analyzer.b bVar = this.E0;
        bVar.a = dVar;
        bVar.b = dVar2;
        bVar.c = i;
        bVar.d = i2;
        cVar.b(eVar, bVar);
        eVar.S(bVar.e);
        eVar.N(bVar.f);
        eVar.F = bVar.h;
        eVar.J(bVar.g);
    }
}

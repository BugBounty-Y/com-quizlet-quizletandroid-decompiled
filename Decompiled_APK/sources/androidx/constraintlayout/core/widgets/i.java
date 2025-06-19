package androidx.constraintlayout.core.widgets;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class i extends e {
    public float t0 = -1.0f;
    public int u0 = -1;
    public int v0 = -1;
    public c w0 = this.L;
    public int x0 = 0;
    public boolean y0;

    public i() {
        this.T.clear();
        this.T.add(this.w0);
        int length = this.S.length;
        for (int i = 0; i < length; i++) {
            this.S[i] = this.w0;
        }
    }

    @Override // androidx.constraintlayout.core.widgets.e
    public final boolean B() {
        return this.y0;
    }

    @Override // androidx.constraintlayout.core.widgets.e
    public final boolean C() {
        return this.y0;
    }

    @Override // androidx.constraintlayout.core.widgets.e
    public final void U(androidx.constraintlayout.core.c cVar, boolean z) {
        if (this.W == null) {
            return;
        }
        c cVar2 = this.w0;
        cVar.getClass();
        int iN = androidx.constraintlayout.core.c.n(cVar2);
        if (this.x0 == 1) {
            this.b0 = iN;
            this.c0 = 0;
            N(this.W.l());
            S(0);
            return;
        }
        this.b0 = 0;
        this.c0 = iN;
        S(this.W.r());
        N(0);
    }

    public final void V(int i) {
        this.w0.l(i);
        this.y0 = true;
    }

    public final void W(int i) {
        if (this.x0 == i) {
            return;
        }
        this.x0 = i;
        ArrayList arrayList = this.T;
        arrayList.clear();
        if (this.x0 == 1) {
            this.w0 = this.K;
        } else {
            this.w0 = this.L;
        }
        arrayList.add(this.w0);
        c[] cVarArr = this.S;
        int length = cVarArr.length;
        for (int i2 = 0; i2 < length; i2++) {
            cVarArr[i2] = this.w0;
        }
    }

    @Override // androidx.constraintlayout.core.widgets.e
    public final void c(androidx.constraintlayout.core.c cVar, boolean z) {
        f fVar = (f) this.W;
        if (fVar == null) {
            return;
        }
        Object objJ = fVar.j(2);
        Object objJ2 = fVar.j(4);
        e eVar = this.W;
        d dVar = d.b;
        boolean z2 = eVar != null && eVar.V[0] == dVar;
        if (this.x0 == 0) {
            objJ = fVar.j(3);
            objJ2 = fVar.j(5);
            e eVar2 = this.W;
            z2 = eVar2 != null && eVar2.V[1] == dVar;
        }
        if (this.y0) {
            c cVar2 = this.w0;
            if (cVar2.c) {
                androidx.constraintlayout.core.g gVarK = cVar.k(cVar2);
                cVar.d(gVarK, this.w0.d());
                if (this.u0 != -1) {
                    if (z2) {
                        cVar.f(cVar.k(objJ2), gVarK, 0, 5);
                    }
                } else if (this.v0 != -1 && z2) {
                    androidx.constraintlayout.core.g gVarK2 = cVar.k(objJ2);
                    cVar.f(gVarK, cVar.k(objJ), 0, 5);
                    cVar.f(gVarK2, gVarK, 0, 5);
                }
                this.y0 = false;
                return;
            }
        }
        if (this.u0 != -1) {
            androidx.constraintlayout.core.g gVarK3 = cVar.k(this.w0);
            cVar.e(gVarK3, cVar.k(objJ), this.u0, 8);
            if (z2) {
                cVar.f(cVar.k(objJ2), gVarK3, 0, 5);
                return;
            }
            return;
        }
        if (this.v0 != -1) {
            androidx.constraintlayout.core.g gVarK4 = cVar.k(this.w0);
            androidx.constraintlayout.core.g gVarK5 = cVar.k(objJ2);
            cVar.e(gVarK4, gVarK5, -this.v0, 8);
            if (z2) {
                cVar.f(gVarK4, cVar.k(objJ), 0, 5);
                cVar.f(gVarK5, gVarK4, 0, 5);
                return;
            }
            return;
        }
        if (this.t0 != -1.0f) {
            androidx.constraintlayout.core.g gVarK6 = cVar.k(this.w0);
            androidx.constraintlayout.core.g gVarK7 = cVar.k(objJ2);
            float f = this.t0;
            androidx.constraintlayout.core.b bVarL = cVar.l();
            bVarL.d.g(gVarK6, -1.0f);
            bVarL.d.g(gVarK7, f);
            cVar.c(bVarL);
        }
    }

    @Override // androidx.constraintlayout.core.widgets.e
    public final boolean d() {
        return true;
    }

    @Override // androidx.constraintlayout.core.widgets.e
    public final c j(int i) {
        int iK = AbstractC0147y.k(i);
        if (iK != 1) {
            if (iK != 2) {
                if (iK != 3) {
                    if (iK != 4) {
                        return null;
                    }
                }
            }
            if (this.x0 == 0) {
                return this.w0;
            }
            return null;
        }
        if (this.x0 == 1) {
            return this.w0;
        }
        return null;
    }
}

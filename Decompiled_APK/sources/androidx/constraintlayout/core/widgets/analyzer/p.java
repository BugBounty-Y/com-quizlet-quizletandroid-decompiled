package androidx.constraintlayout.core.widgets.analyzer;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes.dex */
public abstract class p implements e {
    public int a;
    public androidx.constraintlayout.core.widgets.e b;
    public m c;
    public androidx.constraintlayout.core.widgets.d d;
    public final h e = new h(this);
    public int f = 0;
    public boolean g = false;
    public final g h = new g(this);
    public final g i = new g(this);
    public int j = 1;

    public p(androidx.constraintlayout.core.widgets.e eVar) {
        this.b = eVar;
    }

    public static void b(g gVar, g gVar2, int i) {
        gVar.l.add(gVar2);
        gVar.f = i;
        gVar2.k.add(gVar);
    }

    public static g h(androidx.constraintlayout.core.widgets.c cVar) {
        androidx.constraintlayout.core.widgets.c cVar2 = cVar.f;
        if (cVar2 == null) {
            return null;
        }
        androidx.constraintlayout.core.widgets.e eVar = cVar2.d;
        int iK = AbstractC0147y.k(cVar2.e);
        if (iK == 1) {
            return eVar.d.h;
        }
        if (iK == 2) {
            return eVar.e.h;
        }
        if (iK == 3) {
            return eVar.d.i;
        }
        if (iK == 4) {
            return eVar.e.i;
        }
        if (iK != 5) {
            return null;
        }
        return eVar.e.k;
    }

    public static g i(androidx.constraintlayout.core.widgets.c cVar, int i) {
        androidx.constraintlayout.core.widgets.c cVar2 = cVar.f;
        if (cVar2 == null) {
            return null;
        }
        androidx.constraintlayout.core.widgets.e eVar = cVar2.d;
        p pVar = i == 0 ? eVar.d : eVar.e;
        int iK = AbstractC0147y.k(cVar2.e);
        if (iK == 1 || iK == 2) {
            return pVar.h;
        }
        if (iK == 3 || iK == 4) {
            return pVar.i;
        }
        return null;
    }

    public final void c(g gVar, g gVar2, int i, h hVar) {
        gVar.l.add(gVar2);
        gVar.l.add(this.e);
        gVar.h = i;
        gVar.i = hVar;
        gVar2.k.add(gVar);
        hVar.k.add(gVar);
    }

    public abstract void d();

    public abstract void e();

    public abstract void f();

    public final int g(int i, int i2) {
        if (i2 == 0) {
            androidx.constraintlayout.core.widgets.e eVar = this.b;
            int i3 = eVar.w;
            int iMax = Math.max(eVar.v, i);
            if (i3 > 0) {
                iMax = Math.min(i3, i);
            }
            if (iMax != i) {
                return iMax;
            }
        } else {
            androidx.constraintlayout.core.widgets.e eVar2 = this.b;
            int i4 = eVar2.z;
            int iMax2 = Math.max(eVar2.y, i);
            if (i4 > 0) {
                iMax2 = Math.min(i4, i);
            }
            if (iMax2 != i) {
                return iMax2;
            }
        }
        return i;
    }

    public long j() {
        if (this.e.j) {
            return r0.g;
        }
        return 0L;
    }

    public abstract boolean k();

    /* JADX WARN: Removed duplicated region for block: B:29:0x0056  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void l(androidx.constraintlayout.core.widgets.c r13, androidx.constraintlayout.core.widgets.c r14, int r15) {
        /*
            Method dump skipped, instructions count: 236
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.widgets.analyzer.p.l(androidx.constraintlayout.core.widgets.c, androidx.constraintlayout.core.widgets.c, int):void");
    }
}

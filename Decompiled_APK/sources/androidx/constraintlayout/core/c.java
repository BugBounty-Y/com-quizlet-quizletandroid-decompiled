package androidx.constraintlayout.core;

import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Arrays;

/* loaded from: classes.dex */
public final class c {
    public static boolean q = false;
    public final f d;
    public final com.quizlet.data.interactor.set.c m;
    public b p;
    public int a = 1000;
    public boolean b = false;
    public int c = 0;
    public int e = 32;
    public int f = 32;
    public boolean h = false;
    public boolean[] i = new boolean[32];
    public int j = 1;
    public int k = 0;
    public int l = 32;
    public g[] n = new g[1000];
    public int o = 0;
    public b[] g = new b[32];

    public c() {
        s();
        com.quizlet.data.interactor.set.c cVar = new com.quizlet.data.interactor.set.c();
        cVar.a = new d();
        cVar.b = new d();
        cVar.c = new g[32];
        this.m = cVar;
        f fVar = new f(cVar);
        fVar.f = new g[128];
        fVar.g = new g[128];
        fVar.h = 0;
        fVar.i = new com.quizlet.data.repository.widget.b(fVar);
        this.d = fVar;
        this.p = new b(cVar);
    }

    public static int n(Object obj) {
        g gVar = ((androidx.constraintlayout.core.widgets.c) obj).i;
        if (gVar != null) {
            return (int) (gVar.e + 0.5f);
        }
        return 0;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r3v0, types: [java.lang.Object[]] */
    /* JADX WARN: Type inference failed for: r4v0 */
    public final g a(int i) {
        d dVar = (d) this.m.b;
        int i2 = dVar.b;
        g gVar = null;
        if (i2 > 0) {
            int i3 = i2 - 1;
            ?? r3 = dVar.a;
            ?? r4 = r3[i3];
            r3[i3] = 0;
            dVar.b = i3;
            gVar = r4;
        }
        g gVar2 = gVar;
        if (gVar2 == null) {
            gVar2 = new g(i);
            gVar2.l = i;
        } else {
            gVar2.c();
            gVar2.l = i;
        }
        int i4 = this.o;
        int i5 = this.a;
        if (i4 >= i5) {
            int i6 = i5 * 2;
            this.a = i6;
            this.n = (g[]) Arrays.copyOf(this.n, i6);
        }
        g[] gVarArr = this.n;
        int i7 = this.o;
        this.o = i7 + 1;
        gVarArr[i7] = gVar2;
        return gVar2;
    }

    public final void b(g gVar, g gVar2, int i, float f, g gVar3, g gVar4, int i2, int i3) {
        b bVarL = l();
        if (gVar2 == gVar3) {
            bVarL.d.g(gVar, 1.0f);
            bVarL.d.g(gVar4, 1.0f);
            bVarL.d.g(gVar2, -2.0f);
        } else if (f == 0.5f) {
            bVarL.d.g(gVar, 1.0f);
            bVarL.d.g(gVar2, -1.0f);
            bVarL.d.g(gVar3, -1.0f);
            bVarL.d.g(gVar4, 1.0f);
            if (i > 0 || i2 > 0) {
                bVarL.b = (-i) + i2;
            }
        } else if (f <= DefinitionKt.NO_Float_VALUE) {
            bVarL.d.g(gVar, -1.0f);
            bVarL.d.g(gVar2, 1.0f);
            bVarL.b = i;
        } else if (f >= 1.0f) {
            bVarL.d.g(gVar4, -1.0f);
            bVarL.d.g(gVar3, 1.0f);
            bVarL.b = -i2;
        } else {
            float f2 = 1.0f - f;
            bVarL.d.g(gVar, f2 * 1.0f);
            bVarL.d.g(gVar2, f2 * (-1.0f));
            bVarL.d.g(gVar3, (-1.0f) * f);
            bVarL.d.g(gVar4, 1.0f * f);
            if (i > 0 || i2 > 0) {
                bVarL.b = (i2 * f) + ((-i) * f2);
            }
        }
        if (i3 != 8) {
            bVarL.a(this, i3);
        }
        c(bVarL);
    }

    /* JADX WARN: Removed duplicated region for block: B:121:0x01ae  */
    /* JADX WARN: Removed duplicated region for block: B:124:0x01b3  */
    /* JADX WARN: Removed duplicated region for block: B:157:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:59:0x00d6  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x00f8  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void c(androidx.constraintlayout.core.b r18) {
        /*
            Method dump skipped, instructions count: 453
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.c.c(androidx.constraintlayout.core.b):void");
    }

    public final void d(g gVar, int i) {
        int i2 = gVar.c;
        if (i2 == -1) {
            gVar.d(this, i);
            for (int i3 = 0; i3 < this.c + 1; i3++) {
                g gVar2 = ((g[]) this.m.c)[i3];
            }
            return;
        }
        if (i2 == -1) {
            b bVarL = l();
            bVarL.a = gVar;
            float f = i;
            gVar.e = f;
            bVarL.b = f;
            bVarL.e = true;
            c(bVarL);
            return;
        }
        b bVar = this.g[i2];
        if (bVar.e) {
            bVar.b = i;
            return;
        }
        if (bVar.d.d() == 0) {
            bVar.e = true;
            bVar.b = i;
            return;
        }
        b bVarL2 = l();
        if (i < 0) {
            bVarL2.b = i * (-1);
            bVarL2.d.g(gVar, 1.0f);
        } else {
            bVarL2.b = i;
            bVarL2.d.g(gVar, -1.0f);
        }
        c(bVarL2);
    }

    public final void e(g gVar, g gVar2, int i, int i2) {
        if (i2 == 8 && gVar2.f && gVar.c == -1) {
            gVar.d(this, gVar2.e + i);
            return;
        }
        b bVarL = l();
        boolean z = false;
        if (i != 0) {
            if (i < 0) {
                i *= -1;
                z = true;
            }
            bVarL.b = i;
        }
        if (z) {
            bVarL.d.g(gVar, 1.0f);
            bVarL.d.g(gVar2, -1.0f);
        } else {
            bVarL.d.g(gVar, -1.0f);
            bVarL.d.g(gVar2, 1.0f);
        }
        if (i2 != 8) {
            bVarL.a(this, i2);
        }
        c(bVarL);
    }

    public final void f(g gVar, g gVar2, int i, int i2) {
        b bVarL = l();
        g gVarM = m();
        gVarM.d = 0;
        bVarL.b(gVar, gVar2, gVarM, i);
        if (i2 != 8) {
            bVarL.d.g(j(i2), (int) (bVarL.d.c(gVarM) * (-1.0f)));
        }
        c(bVarL);
    }

    public final void g(g gVar, g gVar2, int i, int i2) {
        b bVarL = l();
        g gVarM = m();
        gVarM.d = 0;
        bVarL.c(gVar, gVar2, gVarM, i);
        if (i2 != 8) {
            bVarL.d.g(j(i2), (int) (bVarL.d.c(gVarM) * (-1.0f)));
        }
        c(bVarL);
    }

    public final void h(b bVar) {
        int i;
        if (bVar.e) {
            bVar.a.d(this, bVar.b);
        } else {
            b[] bVarArr = this.g;
            int i2 = this.k;
            bVarArr[i2] = bVar;
            g gVar = bVar.a;
            gVar.c = i2;
            this.k = i2 + 1;
            gVar.e(this, bVar);
        }
        if (this.b) {
            int i3 = 0;
            while (i3 < this.k) {
                if (this.g[i3] == null) {
                    System.out.println("WTF");
                }
                b bVar2 = this.g[i3];
                if (bVar2 != null && bVar2.e) {
                    bVar2.a.d(this, bVar2.b);
                    ((d) this.m.a).b(bVar2);
                    this.g[i3] = null;
                    int i4 = i3 + 1;
                    int i5 = i4;
                    while (true) {
                        i = this.k;
                        if (i4 >= i) {
                            break;
                        }
                        b[] bVarArr2 = this.g;
                        int i6 = i4 - 1;
                        b bVar3 = bVarArr2[i4];
                        bVarArr2[i6] = bVar3;
                        g gVar2 = bVar3.a;
                        if (gVar2.c == i4) {
                            gVar2.c = i6;
                        }
                        i5 = i4;
                        i4++;
                    }
                    if (i5 < i) {
                        this.g[i5] = null;
                    }
                    this.k = i - 1;
                    i3--;
                }
                i3++;
            }
            this.b = false;
        }
    }

    public final void i() {
        for (int i = 0; i < this.k; i++) {
            b bVar = this.g[i];
            bVar.a.e = bVar.b;
        }
    }

    public final g j(int i) {
        if (this.j + 1 >= this.f) {
            o();
        }
        g gVarA = a(4);
        int i2 = this.c + 1;
        this.c = i2;
        this.j++;
        gVarA.b = i2;
        gVarA.d = i;
        ((g[]) this.m.c)[i2] = gVarA;
        f fVar = this.d;
        fVar.i.b = gVarA;
        float[] fArr = gVarA.h;
        Arrays.fill(fArr, DefinitionKt.NO_Float_VALUE);
        fArr[gVarA.d] = 1.0f;
        fVar.j(gVarA);
        return gVarA;
    }

    public final g k(Object obj) {
        if (obj == null) {
            return null;
        }
        if (this.j + 1 >= this.f) {
            o();
        }
        if (!(obj instanceof androidx.constraintlayout.core.widgets.c)) {
            return null;
        }
        androidx.constraintlayout.core.widgets.c cVar = (androidx.constraintlayout.core.widgets.c) obj;
        g gVar = cVar.i;
        if (gVar == null) {
            cVar.k();
            gVar = cVar.i;
        }
        int i = gVar.b;
        com.quizlet.data.interactor.set.c cVar2 = this.m;
        if (i != -1 && i <= this.c && ((g[]) cVar2.c)[i] != null) {
            return gVar;
        }
        if (i != -1) {
            gVar.c();
        }
        int i2 = this.c + 1;
        this.c = i2;
        this.j++;
        gVar.b = i2;
        gVar.l = 1;
        ((g[]) cVar2.c)[i2] = gVar;
        return gVar;
    }

    public final b l() {
        Object obj;
        com.quizlet.data.interactor.set.c cVar = this.m;
        d dVar = (d) cVar.a;
        int i = dVar.b;
        if (i > 0) {
            int i2 = i - 1;
            Object[] objArr = dVar.a;
            obj = objArr[i2];
            objArr[i2] = null;
            dVar.b = i2;
        } else {
            obj = null;
        }
        b bVar = (b) obj;
        if (bVar == null) {
            return new b(cVar);
        }
        bVar.a = null;
        bVar.d.b();
        bVar.b = DefinitionKt.NO_Float_VALUE;
        bVar.e = false;
        return bVar;
    }

    public final g m() {
        if (this.j + 1 >= this.f) {
            o();
        }
        g gVarA = a(3);
        int i = this.c + 1;
        this.c = i;
        this.j++;
        gVarA.b = i;
        ((g[]) this.m.c)[i] = gVarA;
        return gVarA;
    }

    public final void o() {
        int i = this.e * 2;
        this.e = i;
        this.g = (b[]) Arrays.copyOf(this.g, i);
        com.quizlet.data.interactor.set.c cVar = this.m;
        cVar.c = (g[]) Arrays.copyOf((g[]) cVar.c, this.e);
        int i2 = this.e;
        this.i = new boolean[i2];
        this.f = i2;
        this.l = i2;
    }

    public final void p() {
        f fVar = this.d;
        if (fVar.e()) {
            i();
            return;
        }
        if (!this.h) {
            q(fVar);
            return;
        }
        for (int i = 0; i < this.k; i++) {
            if (!this.g[i].e) {
                q(fVar);
                return;
            }
        }
        i();
    }

    public final void q(f fVar) {
        int i = 0;
        while (true) {
            if (i >= this.k) {
                break;
            }
            b bVar = this.g[i];
            int i2 = 1;
            if (bVar.a.l != 1) {
                float f = bVar.b;
                float f2 = DefinitionKt.NO_Float_VALUE;
                if (f < DefinitionKt.NO_Float_VALUE) {
                    boolean z = false;
                    int i3 = 0;
                    while (!z) {
                        i3 += i2;
                        float f3 = Float.MAX_VALUE;
                        int i4 = -1;
                        int i5 = -1;
                        int i6 = 0;
                        int i7 = 0;
                        while (i6 < this.k) {
                            b bVar2 = this.g[i6];
                            if (bVar2.a.l != i2 && !bVar2.e && bVar2.b < f2) {
                                int iD = bVar2.d.d();
                                int i8 = 0;
                                while (i8 < iD) {
                                    g gVarE = bVar2.d.e(i8);
                                    float fC = bVar2.d.c(gVarE);
                                    if (fC > f2) {
                                        for (int i9 = 0; i9 < 9; i9++) {
                                            float f4 = gVarE.g[i9] / fC;
                                            if ((f4 < f3 && i9 == i7) || i9 > i7) {
                                                i7 = i9;
                                                i5 = gVarE.b;
                                                i4 = i6;
                                                f3 = f4;
                                            }
                                        }
                                    }
                                    i8++;
                                    f2 = DefinitionKt.NO_Float_VALUE;
                                }
                            }
                            i6++;
                            f2 = DefinitionKt.NO_Float_VALUE;
                            i2 = 1;
                        }
                        if (i4 != -1) {
                            b bVar3 = this.g[i4];
                            bVar3.a.c = -1;
                            bVar3.g(((g[]) this.m.c)[i5]);
                            g gVar = bVar3.a;
                            gVar.c = i4;
                            gVar.e(this, bVar3);
                        } else {
                            z = true;
                        }
                        if (i3 > this.j / 2) {
                            z = true;
                        }
                        f2 = DefinitionKt.NO_Float_VALUE;
                        i2 = 1;
                    }
                }
            }
            i++;
        }
        r(fVar);
        i();
    }

    /* JADX WARN: Removed duplicated region for block: B:43:0x007d  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x0092 A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void r(androidx.constraintlayout.core.b r17) {
        /*
            Method dump skipped, instructions count: 177
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.c.r(androidx.constraintlayout.core.b):void");
    }

    public final void s() {
        for (int i = 0; i < this.k; i++) {
            b bVar = this.g[i];
            if (bVar != null) {
                ((d) this.m.a).b(bVar);
            }
            this.g[i] = null;
        }
    }

    public final void t() {
        com.quizlet.data.interactor.set.c cVar;
        int i = 0;
        while (true) {
            cVar = this.m;
            g[] gVarArr = (g[]) cVar.c;
            if (i >= gVarArr.length) {
                break;
            }
            g gVar = gVarArr[i];
            if (gVar != null) {
                gVar.c();
            }
            i++;
        }
        d dVar = (d) cVar.b;
        g[] gVarArr2 = this.n;
        int length = this.o;
        dVar.getClass();
        if (length > gVarArr2.length) {
            length = gVarArr2.length;
        }
        for (int i2 = 0; i2 < length; i2++) {
            g gVar2 = gVarArr2[i2];
            int i3 = dVar.b;
            Object[] objArr = dVar.a;
            if (i3 < objArr.length) {
                objArr[i3] = gVar2;
                dVar.b = i3 + 1;
            }
        }
        this.o = 0;
        Arrays.fill((g[]) cVar.c, (Object) null);
        this.c = 0;
        f fVar = this.d;
        fVar.h = 0;
        fVar.b = DefinitionKt.NO_Float_VALUE;
        this.j = 1;
        for (int i4 = 0; i4 < this.k; i4++) {
            b bVar = this.g[i4];
        }
        s();
        this.k = 0;
        this.p = new b(cVar);
    }
}

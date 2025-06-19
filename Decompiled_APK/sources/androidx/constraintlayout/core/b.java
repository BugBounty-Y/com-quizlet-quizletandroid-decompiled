package androidx.constraintlayout.core;

import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;

/* loaded from: classes.dex */
public class b {
    public final a d;
    public g a = null;
    public float b = DefinitionKt.NO_Float_VALUE;
    public final ArrayList c = new ArrayList();
    public boolean e = false;

    public b(com.quizlet.data.interactor.set.c cVar) {
        this.d = new a(this, cVar);
    }

    public final void a(c cVar, int i) {
        this.d.g(cVar.j(i), 1.0f);
        this.d.g(cVar.j(i), -1.0f);
    }

    public final void b(g gVar, g gVar2, g gVar3, int i) {
        boolean z = false;
        if (i != 0) {
            if (i < 0) {
                i *= -1;
                z = true;
            }
            this.b = i;
        }
        if (z) {
            this.d.g(gVar, 1.0f);
            this.d.g(gVar2, -1.0f);
            this.d.g(gVar3, -1.0f);
        } else {
            this.d.g(gVar, -1.0f);
            this.d.g(gVar2, 1.0f);
            this.d.g(gVar3, 1.0f);
        }
    }

    public final void c(g gVar, g gVar2, g gVar3, int i) {
        boolean z = false;
        if (i != 0) {
            if (i < 0) {
                i *= -1;
                z = true;
            }
            this.b = i;
        }
        if (z) {
            this.d.g(gVar, 1.0f);
            this.d.g(gVar2, -1.0f);
            this.d.g(gVar3, 1.0f);
        } else {
            this.d.g(gVar, -1.0f);
            this.d.g(gVar2, 1.0f);
            this.d.g(gVar3, -1.0f);
        }
    }

    public g d(boolean[] zArr) {
        return f(zArr, null);
    }

    public boolean e() {
        return this.a == null && this.b == DefinitionKt.NO_Float_VALUE && this.d.d() == 0;
    }

    public final g f(boolean[] zArr, g gVar) {
        int i;
        int iD = this.d.d();
        g gVar2 = null;
        float f = 0.0f;
        for (int i2 = 0; i2 < iD; i2++) {
            float f2 = this.d.f(i2);
            if (f2 < DefinitionKt.NO_Float_VALUE) {
                g gVarE = this.d.e(i2);
                if ((zArr == null || !zArr[gVarE.b]) && gVarE != gVar && (((i = gVarE.l) == 3 || i == 4) && f2 < f)) {
                    f = f2;
                    gVar2 = gVarE;
                }
            }
        }
        return gVar2;
    }

    public final void g(g gVar) {
        g gVar2 = this.a;
        if (gVar2 != null) {
            this.d.g(gVar2, -1.0f);
            this.a.c = -1;
            this.a = null;
        }
        float fH = this.d.h(gVar, true) * (-1.0f);
        this.a = gVar;
        if (fH == 1.0f) {
            return;
        }
        this.b /= fH;
        a aVar = this.d;
        int i = aVar.h;
        for (int i2 = 0; i != -1 && i2 < aVar.a; i2++) {
            float[] fArr = aVar.g;
            fArr[i] = fArr[i] / fH;
            i = aVar.f[i];
        }
    }

    public final void h(c cVar, g gVar, boolean z) {
        if (gVar == null || !gVar.f) {
            return;
        }
        float fC = this.d.c(gVar);
        this.b = (gVar.e * fC) + this.b;
        this.d.h(gVar, z);
        if (z) {
            gVar.b(this);
        }
        if (this.d.d() == 0) {
            this.e = true;
            cVar.b = true;
        }
    }

    public void i(c cVar, b bVar, boolean z) {
        a aVar = this.d;
        aVar.getClass();
        float fC = aVar.c(bVar.a);
        aVar.h(bVar.a, z);
        a aVar2 = bVar.d;
        int iD = aVar2.d();
        for (int i = 0; i < iD; i++) {
            g gVarE = aVar2.e(i);
            aVar.a(gVarE, aVar2.c(gVarE) * fC, z);
        }
        this.b = (bVar.b * fC) + this.b;
        if (z) {
            bVar.a.b(this);
        }
        if (this.a == null || this.d.d() != 0) {
            return;
        }
        this.e = true;
        cVar.b = true;
    }

    /* JADX WARN: Removed duplicated region for block: B:29:0x007c  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x0081  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.String toString() {
        /*
            r10 = this;
            androidx.constraintlayout.core.g r0 = r10.a
            if (r0 != 0) goto L7
            java.lang.String r0 = "0"
            goto L17
        L7:
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            java.lang.String r1 = ""
            r0.<init>(r1)
            androidx.constraintlayout.core.g r1 = r10.a
            r0.append(r1)
            java.lang.String r0 = r0.toString()
        L17:
            java.lang.String r1 = " = "
            java.lang.String r0 = android.support.v4.media.session.a.k(r0, r1)
            float r1 = r10.b
            r2 = 0
            int r1 = (r1 > r2 ? 1 : (r1 == r2 ? 0 : -1))
            r3 = 1
            r4 = 0
            if (r1 == 0) goto L35
            java.lang.StringBuilder r0 = androidx.compose.animation.d0.u(r0)
            float r1 = r10.b
            r0.append(r1)
            java.lang.String r0 = r0.toString()
            r1 = r3
            goto L36
        L35:
            r1 = r4
        L36:
            androidx.constraintlayout.core.a r5 = r10.d
            int r5 = r5.d()
        L3c:
            if (r4 >= r5) goto L9c
            androidx.constraintlayout.core.a r6 = r10.d
            androidx.constraintlayout.core.g r6 = r6.e(r4)
            if (r6 != 0) goto L47
            goto L99
        L47:
            androidx.constraintlayout.core.a r7 = r10.d
            float r7 = r7.f(r4)
            int r8 = (r7 > r2 ? 1 : (r7 == r2 ? 0 : -1))
            if (r8 != 0) goto L52
            goto L99
        L52:
            java.lang.String r6 = r6.toString()
            r9 = -1082130432(0xffffffffbf800000, float:-1.0)
            if (r1 != 0) goto L66
            int r1 = (r7 > r2 ? 1 : (r7 == r2 ? 0 : -1))
            if (r1 >= 0) goto L76
            java.lang.String r1 = "- "
            java.lang.String r0 = android.support.v4.media.session.a.k(r0, r1)
        L64:
            float r7 = r7 * r9
            goto L76
        L66:
            if (r8 <= 0) goto L6f
            java.lang.String r1 = " + "
            java.lang.String r0 = android.support.v4.media.session.a.k(r0, r1)
            goto L76
        L6f:
            java.lang.String r1 = " - "
            java.lang.String r0 = android.support.v4.media.session.a.k(r0, r1)
            goto L64
        L76:
            r1 = 1065353216(0x3f800000, float:1.0)
            int r1 = (r7 > r1 ? 1 : (r7 == r1 ? 0 : -1))
            if (r1 != 0) goto L81
            java.lang.String r0 = android.support.v4.media.session.a.k(r0, r6)
            goto L98
        L81:
            java.lang.StringBuilder r1 = new java.lang.StringBuilder
            r1.<init>()
            r1.append(r0)
            r1.append(r7)
            java.lang.String r0 = " "
            r1.append(r0)
            r1.append(r6)
            java.lang.String r0 = r1.toString()
        L98:
            r1 = r3
        L99:
            int r4 = r4 + 1
            goto L3c
        L9c:
            if (r1 != 0) goto La4
            java.lang.String r1 = "0.0"
            java.lang.String r0 = android.support.v4.media.session.a.k(r0, r1)
        La4:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.b.toString():java.lang.String");
    }
}

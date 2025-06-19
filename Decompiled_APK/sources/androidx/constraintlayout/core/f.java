package androidx.constraintlayout.core;

import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Arrays;

/* loaded from: classes.dex */
public final class f extends b {
    public g[] f;
    public g[] g;
    public int h;
    public com.quizlet.data.repository.widget.b i;

    @Override // androidx.constraintlayout.core.b
    public final g d(boolean[] zArr) {
        int i = -1;
        for (int i2 = 0; i2 < this.h; i2++) {
            g[] gVarArr = this.f;
            g gVar = gVarArr[i2];
            if (!zArr[gVar.b]) {
                com.quizlet.data.repository.widget.b bVar = this.i;
                bVar.b = gVar;
                int i3 = 8;
                if (i == -1) {
                    while (i3 >= 0) {
                        float f = ((g) bVar.b).h[i3];
                        if (f <= DefinitionKt.NO_Float_VALUE) {
                            if (f < DefinitionKt.NO_Float_VALUE) {
                                i = i2;
                                break;
                            }
                            i3--;
                        }
                    }
                } else {
                    g gVar2 = gVarArr[i];
                    while (true) {
                        if (i3 >= 0) {
                            float f2 = gVar2.h[i3];
                            float f3 = ((g) bVar.b).h[i3];
                            if (f3 == f2) {
                                i3--;
                            } else if (f3 < f2) {
                            }
                        }
                    }
                }
            }
        }
        if (i == -1) {
            return null;
        }
        return this.f[i];
    }

    @Override // androidx.constraintlayout.core.b
    public final boolean e() {
        return this.h == 0;
    }

    @Override // androidx.constraintlayout.core.b
    public final void i(c cVar, b bVar, boolean z) {
        g gVar = bVar.a;
        if (gVar == null) {
            return;
        }
        a aVar = bVar.d;
        int iD = aVar.d();
        for (int i = 0; i < iD; i++) {
            g gVarE = aVar.e(i);
            float f = aVar.f(i);
            com.quizlet.data.repository.widget.b bVar2 = this.i;
            bVar2.b = gVarE;
            boolean z2 = gVarE.a;
            float[] fArr = gVar.h;
            if (z2) {
                boolean z3 = true;
                for (int i2 = 0; i2 < 9; i2++) {
                    float[] fArr2 = ((g) bVar2.b).h;
                    float f2 = (fArr[i2] * f) + fArr2[i2];
                    fArr2[i2] = f2;
                    if (Math.abs(f2) < 1.0E-4f) {
                        ((g) bVar2.b).h[i2] = 0.0f;
                    } else {
                        z3 = false;
                    }
                }
                if (z3) {
                    ((f) bVar2.c).k((g) bVar2.b);
                }
            } else {
                for (int i3 = 0; i3 < 9; i3++) {
                    float f3 = fArr[i3];
                    if (f3 != DefinitionKt.NO_Float_VALUE) {
                        float f4 = f3 * f;
                        if (Math.abs(f4) < 1.0E-4f) {
                            f4 = 0.0f;
                        }
                        ((g) bVar2.b).h[i3] = f4;
                    } else {
                        ((g) bVar2.b).h[i3] = 0.0f;
                    }
                }
                j(gVarE);
            }
            this.b = (bVar.b * f) + this.b;
        }
        k(gVar);
    }

    public final void j(g gVar) {
        int i;
        int i2 = this.h + 1;
        g[] gVarArr = this.f;
        if (i2 > gVarArr.length) {
            g[] gVarArr2 = (g[]) Arrays.copyOf(gVarArr, gVarArr.length * 2);
            this.f = gVarArr2;
            this.g = (g[]) Arrays.copyOf(gVarArr2, gVarArr2.length * 2);
        }
        g[] gVarArr3 = this.f;
        int i3 = this.h;
        gVarArr3[i3] = gVar;
        int i4 = i3 + 1;
        this.h = i4;
        if (i4 > 1 && gVarArr3[i3].b > gVar.b) {
            int i5 = 0;
            while (true) {
                i = this.h;
                if (i5 >= i) {
                    break;
                }
                this.g[i5] = this.f[i5];
                i5++;
            }
            Arrays.sort(this.g, 0, i, new e(0));
            for (int i6 = 0; i6 < this.h; i6++) {
                this.f[i6] = this.g[i6];
            }
        }
        gVar.a = true;
        gVar.a(this);
    }

    public final void k(g gVar) {
        int i = 0;
        while (i < this.h) {
            if (this.f[i] == gVar) {
                while (true) {
                    int i2 = this.h;
                    if (i >= i2 - 1) {
                        this.h = i2 - 1;
                        gVar.a = false;
                        return;
                    } else {
                        g[] gVarArr = this.f;
                        int i3 = i + 1;
                        gVarArr[i] = gVarArr[i3];
                        i = i3;
                    }
                }
            } else {
                i++;
            }
        }
    }

    @Override // androidx.constraintlayout.core.b
    public final String toString() {
        String str = " goal -> (" + this.b + ") : ";
        for (int i = 0; i < this.h; i++) {
            g gVar = this.f[i];
            com.quizlet.data.repository.widget.b bVar = this.i;
            bVar.b = gVar;
            str = str + bVar + " ";
        }
        return str;
    }
}

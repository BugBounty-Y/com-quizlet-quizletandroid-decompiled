package androidx.constraintlayout.core.motion.utils;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3107b6;

/* loaded from: classes.dex */
public final class b extends AbstractC3107b6 {
    public final double[] b;
    public final a[] c;

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:20:0x0037  */
    /* JADX WARN: Type inference failed for: r0v0, types: [androidx.constraintlayout.core.motion.utils.b, java.lang.Object] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public b(int[] r32, double[] r33, double[][] r34) {
        /*
            Method dump skipped, instructions count: 429
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.motion.utils.b.<init>(int[], double[], double[][]):void");
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3107b6
    public final double c(double d) {
        a[] aVarArr = this.c;
        a aVar = aVarArr[0];
        double d2 = aVar.c;
        if (d < d2) {
            double d3 = d - d2;
            if (aVar.r) {
                return (d3 * aVarArr[0].l) + aVar.c(d2);
            }
            aVar.g(d2);
            return (aVarArr[0].a() * d3) + aVarArr[0].e();
        }
        if (d > aVarArr[aVarArr.length - 1].d) {
            double d4 = aVarArr[aVarArr.length - 1].d;
            double d5 = d - d4;
            int length = aVarArr.length - 1;
            return (d5 * aVarArr[length].l) + aVarArr[length].c(d4);
        }
        for (int i = 0; i < aVarArr.length; i++) {
            a aVar2 = aVarArr[i];
            if (d <= aVar2.d) {
                if (aVar2.r) {
                    return aVar2.c(d);
                }
                aVar2.g(d);
                return aVarArr[i].e();
            }
        }
        return Double.NaN;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3107b6
    public final void d(double d, double[] dArr) {
        a[] aVarArr = this.c;
        a aVar = aVarArr[0];
        double d2 = aVar.c;
        if (d < d2) {
            double d3 = d - d2;
            if (aVar.r) {
                double dC = aVar.c(d2);
                a aVar2 = aVarArr[0];
                dArr[0] = (aVar2.l * d3) + dC;
                dArr[1] = (d3 * aVarArr[0].m) + aVar2.d(d2);
                return;
            }
            aVar.g(d2);
            dArr[0] = (aVarArr[0].a() * d3) + aVarArr[0].e();
            dArr[1] = (aVarArr[0].b() * d3) + aVarArr[0].f();
            return;
        }
        if (d <= aVarArr[aVarArr.length - 1].d) {
            for (int i = 0; i < aVarArr.length; i++) {
                a aVar3 = aVarArr[i];
                if (d <= aVar3.d) {
                    if (aVar3.r) {
                        dArr[0] = aVar3.c(d);
                        dArr[1] = aVarArr[i].d(d);
                        return;
                    } else {
                        aVar3.g(d);
                        dArr[0] = aVarArr[i].e();
                        dArr[1] = aVarArr[i].f();
                        return;
                    }
                }
            }
            return;
        }
        double d4 = aVarArr[aVarArr.length - 1].d;
        double d5 = d - d4;
        int length = aVarArr.length - 1;
        a aVar4 = aVarArr[length];
        if (aVar4.r) {
            double dC2 = aVar4.c(d4);
            a aVar5 = aVarArr[length];
            dArr[0] = (aVar5.l * d5) + dC2;
            dArr[1] = (d5 * aVarArr[length].m) + aVar5.d(d4);
            return;
        }
        aVar4.g(d);
        dArr[0] = (aVarArr[length].a() * d5) + aVarArr[length].e();
        dArr[1] = (aVarArr[length].b() * d5) + aVarArr[length].f();
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3107b6
    public final void e(double d, float[] fArr) {
        a[] aVarArr = this.c;
        a aVar = aVarArr[0];
        double d2 = aVar.c;
        if (d < d2) {
            double d3 = d - d2;
            if (aVar.r) {
                double dC = aVar.c(d2);
                a aVar2 = aVarArr[0];
                fArr[0] = (float) ((aVar2.l * d3) + dC);
                fArr[1] = (float) ((d3 * aVarArr[0].m) + aVar2.d(d2));
                return;
            }
            aVar.g(d2);
            fArr[0] = (float) ((aVarArr[0].a() * d3) + aVarArr[0].e());
            fArr[1] = (float) ((aVarArr[0].b() * d3) + aVarArr[0].f());
            return;
        }
        if (d <= aVarArr[aVarArr.length - 1].d) {
            for (int i = 0; i < aVarArr.length; i++) {
                a aVar3 = aVarArr[i];
                if (d <= aVar3.d) {
                    if (aVar3.r) {
                        fArr[0] = (float) aVar3.c(d);
                        fArr[1] = (float) aVarArr[i].d(d);
                        return;
                    } else {
                        aVar3.g(d);
                        fArr[0] = (float) aVarArr[i].e();
                        fArr[1] = (float) aVarArr[i].f();
                        return;
                    }
                }
            }
            return;
        }
        double d4 = aVarArr[aVarArr.length - 1].d;
        double d5 = d - d4;
        int length = aVarArr.length - 1;
        a aVar4 = aVarArr[length];
        if (!aVar4.r) {
            aVar4.g(d);
            fArr[0] = (float) aVarArr[length].e();
            fArr[1] = (float) aVarArr[length].f();
        } else {
            double dC2 = aVar4.c(d4);
            a aVar5 = aVarArr[length];
            fArr[0] = (float) ((aVar5.l * d5) + dC2);
            fArr[1] = (float) ((d5 * aVarArr[length].m) + aVar5.d(d4));
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3107b6
    public final void f(double d, double[] dArr) {
        a[] aVarArr = this.c;
        double d2 = aVarArr[0].c;
        if (d < d2) {
            d = d2;
        } else if (d > aVarArr[aVarArr.length - 1].d) {
            d = aVarArr[aVarArr.length - 1].d;
        }
        for (int i = 0; i < aVarArr.length; i++) {
            a aVar = aVarArr[i];
            if (d <= aVar.d) {
                if (aVar.r) {
                    dArr[0] = aVar.l;
                    dArr[1] = aVar.m;
                    return;
                } else {
                    aVar.g(d);
                    dArr[0] = aVarArr[i].a();
                    dArr[1] = aVarArr[i].b();
                    return;
                }
            }
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3107b6
    public final double[] g() {
        return this.b;
    }
}

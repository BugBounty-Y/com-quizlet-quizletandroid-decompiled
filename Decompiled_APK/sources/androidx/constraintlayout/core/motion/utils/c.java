package androidx.constraintlayout.core.motion.utils;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3107b6;

/* loaded from: classes.dex */
public final class c extends AbstractC3107b6 {
    public double b;
    public double[] c;

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3107b6
    public final double c(double d) {
        return this.c[0];
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3107b6
    public final void d(double d, double[] dArr) {
        double[] dArr2 = this.c;
        System.arraycopy(dArr2, 0, dArr, 0, dArr2.length);
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3107b6
    public final void e(double d, float[] fArr) {
        int i = 0;
        while (true) {
            double[] dArr = this.c;
            if (i >= dArr.length) {
                return;
            }
            fArr[i] = (float) dArr[i];
            i++;
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3107b6
    public final void f(double d, double[] dArr) {
        for (int i = 0; i < this.c.length; i++) {
            dArr[i] = 0.0d;
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3107b6
    public final double[] g() {
        return new double[]{this.b};
    }
}

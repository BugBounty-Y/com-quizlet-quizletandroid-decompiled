package androidx.constraintlayout.motion.utils;

import android.util.SparseArray;
import android.view.View;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3107b6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3125d6;
import com.skydoves.balloon.internals.DefinitionKt;
import java.lang.reflect.Array;

/* loaded from: classes.dex */
public final class m extends p {
    public String j;
    public SparseArray k;
    public SparseArray l;
    public float[] m;

    @Override // androidx.constraintlayout.motion.utils.p
    public final boolean c(float f, long j, View view, androidx.constraintlayout.core.motion.utils.e eVar) {
        this.a.e(f, this.m);
        float[] fArr = this.m;
        float f2 = fArr[fArr.length - 2];
        float f3 = fArr[fArr.length - 1];
        long j2 = j - this.h;
        if (Float.isNaN(this.i)) {
            float fC = eVar.c(view, this.j);
            this.i = fC;
            if (Float.isNaN(fC)) {
                this.i = DefinitionKt.NO_Float_VALUE;
            }
        }
        float f4 = (float) ((((j2 * 1.0E-9d) * f2) + this.i) % 1.0d);
        this.i = f4;
        this.h = j;
        float fA = a(f4);
        this.g = false;
        int i = 0;
        while (true) {
            float[] fArr2 = this.f;
            if (i >= fArr2.length) {
                break;
            }
            boolean z = this.g;
            float f5 = this.m[i];
            this.g = z | (((double) f5) != 0.0d);
            fArr2[i] = (f5 * fA) + f3;
            i++;
        }
        AbstractC3125d6.c((androidx.constraintlayout.widget.b) this.k.valueAt(0), view, this.f);
        if (f2 != DefinitionKt.NO_Float_VALUE) {
            this.g = true;
        }
        return this.g;
    }

    @Override // androidx.constraintlayout.motion.utils.p
    public final void d(int i) {
        SparseArray sparseArray = this.k;
        int size = sparseArray.size();
        int iC = ((androidx.constraintlayout.widget.b) sparseArray.valueAt(0)).c();
        double[] dArr = new double[size];
        int i2 = iC + 2;
        this.m = new float[i2];
        this.f = new float[iC];
        double[][] dArr2 = (double[][]) Array.newInstance((Class<?>) Double.TYPE, size, i2);
        for (int i3 = 0; i3 < size; i3++) {
            int iKeyAt = sparseArray.keyAt(i3);
            androidx.constraintlayout.widget.b bVar = (androidx.constraintlayout.widget.b) sparseArray.valueAt(i3);
            float[] fArr = (float[]) this.l.valueAt(i3);
            dArr[i3] = iKeyAt * 0.01d;
            bVar.b(this.m);
            int i4 = 0;
            while (true) {
                if (i4 < this.m.length) {
                    dArr2[i3][i4] = r10[i4];
                    i4++;
                }
            }
            double[] dArr3 = dArr2[i3];
            dArr3[iC] = fArr[0];
            dArr3[iC + 1] = fArr[1];
        }
        this.a = AbstractC3107b6.b(i, dArr, dArr2);
    }
}

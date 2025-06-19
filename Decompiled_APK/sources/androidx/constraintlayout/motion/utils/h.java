package androidx.constraintlayout.motion.utils;

import android.util.SparseArray;
import android.view.View;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3107b6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3125d6;
import java.lang.reflect.Array;

/* loaded from: classes.dex */
public final class h extends k {
    public SparseArray f;
    public float[] g;

    @Override // androidx.constraintlayout.motion.utils.k
    public final void b(float f, int i) {
        throw new RuntimeException("call of custom attribute setPoint");
    }

    @Override // androidx.constraintlayout.motion.utils.k
    public final void c(View view, float f) {
        this.a.e(f, this.g);
        AbstractC3125d6.c((androidx.constraintlayout.widget.b) this.f.valueAt(0), view, this.g);
    }

    @Override // androidx.constraintlayout.motion.utils.k
    public final void d(int i) {
        SparseArray sparseArray = this.f;
        int size = sparseArray.size();
        int iC = ((androidx.constraintlayout.widget.b) sparseArray.valueAt(0)).c();
        double[] dArr = new double[size];
        this.g = new float[iC];
        double[][] dArr2 = (double[][]) Array.newInstance((Class<?>) Double.TYPE, size, iC);
        for (int i2 = 0; i2 < size; i2++) {
            int iKeyAt = sparseArray.keyAt(i2);
            androidx.constraintlayout.widget.b bVar = (androidx.constraintlayout.widget.b) sparseArray.valueAt(i2);
            dArr[i2] = iKeyAt * 0.01d;
            bVar.b(this.g);
            int i3 = 0;
            while (true) {
                if (i3 < this.g.length) {
                    dArr2[i2][i3] = r7[i3];
                    i3++;
                }
            }
        }
        this.a = AbstractC3107b6.b(i, dArr, dArr2);
    }
}

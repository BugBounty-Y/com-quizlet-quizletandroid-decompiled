package androidx.constraintlayout.motion.utils;

import android.view.View;
import androidx.compose.ui.node.V;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3107b6;
import com.skydoves.balloon.internals.DefinitionKt;
import java.lang.reflect.Array;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;

/* loaded from: classes.dex */
public abstract class f {
    public V a;
    public String b;
    public final int c = 0;
    public final String d = null;
    public final int e = 0;
    public final ArrayList f = new ArrayList();

    public final float a(float f) {
        char c;
        double d;
        double dSignum;
        double dAbs;
        V v = this.a;
        AbstractC3107b6 abstractC3107b6 = (AbstractC3107b6) v.h;
        if (abstractC3107b6 != null) {
            abstractC3107b6.d(f, (double[]) v.i);
        } else {
            double[] dArr = (double[]) v.i;
            dArr[0] = ((float[]) v.f)[0];
            dArr[1] = ((float[]) v.g)[0];
            dArr[2] = ((float[]) v.c)[0];
        }
        double[] dArr2 = (double[]) v.i;
        double d2 = dArr2[0];
        double d3 = dArr2[1];
        double d4 = f;
        androidx.camera.camera2.internal.concurrent.a aVar = (androidx.camera.camera2.internal.concurrent.a) v.b;
        aVar.getClass();
        double d5 = 0.0d;
        if (d4 <= 0.0d) {
            c = 2;
            d = d2;
        } else if (d4 >= 1.0d) {
            c = 2;
            d = d2;
            d5 = 1.0d;
        } else {
            int iBinarySearch = Arrays.binarySearch((double[]) aVar.d, d4);
            if (iBinarySearch < 0) {
                iBinarySearch = (-iBinarySearch) - 1;
            }
            float[] fArr = (float[]) aVar.c;
            float f2 = fArr[iBinarySearch];
            int i = iBinarySearch - 1;
            float f3 = fArr[i];
            c = 2;
            d = d2;
            double[] dArr3 = (double[]) aVar.d;
            double d6 = dArr3[iBinarySearch];
            double d7 = dArr3[i];
            double d8 = (f2 - f3) / (d6 - d7);
            d5 = ((((d4 * d4) - (d7 * d7)) * d8) / 2.0d) + ((d4 - d7) * (f3 - (d8 * d7))) + ((double[]) aVar.e)[i];
        }
        double d9 = d5 + d3;
        switch (aVar.b) {
            case 1:
                dSignum = Math.signum(0.5d - (d9 % 1.0d));
                break;
            case 2:
                dAbs = Math.abs((((d9 * 4.0d) + 1.0d) % 4.0d) - 2.0d);
                dSignum = 1.0d - dAbs;
                break;
            case 3:
                dSignum = (((d9 * 2.0d) + 1.0d) % 2.0d) - 1.0d;
                break;
            case 4:
                dSignum = 1.0d - (((d9 * 2.0d) + 1.0d) % 2.0d);
                break;
            case 5:
                dSignum = Math.cos((d3 + d9) * 6.283185307179586d);
                break;
            case 6:
                double dAbs2 = 1.0d - Math.abs(((d9 * 4.0d) % 4.0d) - 2.0d);
                dAbs = dAbs2 * dAbs2;
                dSignum = 1.0d - dAbs;
                break;
            case 7:
                dSignum = ((androidx.constraintlayout.core.motion.utils.h) aVar.f).c(d9 % 1.0d);
                break;
            default:
                dSignum = Math.sin(6.283185307179586d * d9);
                break;
        }
        return (float) ((dSignum * ((double[]) v.i)[c]) + d);
    }

    public abstract void b(View view, float f);

    public final void c() {
        int i;
        int i2;
        int i3;
        int i4;
        double d;
        int i5;
        ArrayList arrayList = this.f;
        int size = arrayList.size();
        if (size == 0) {
            return;
        }
        Collections.sort(arrayList, new androidx.constraintlayout.core.e(1));
        double[] dArr = new double[size];
        Class cls = Double.TYPE;
        double[][] dArr2 = (double[][]) Array.newInstance((Class<?>) cls, size, 3);
        int i6 = this.c;
        String str = this.d;
        V v = new V();
        androidx.camera.camera2.internal.concurrent.a aVar = new androidx.camera.camera2.internal.concurrent.a();
        aVar.c = new float[0];
        aVar.d = new double[0];
        v.b = aVar;
        aVar.b = i6;
        if (str != null) {
            double[] dArr3 = new double[str.length() / 2];
            i3 = 3;
            int iIndexOf = str.indexOf(40) + 1;
            i4 = 0;
            i2 = 1;
            int iIndexOf2 = str.indexOf(44, iIndexOf);
            int i7 = 0;
            d = 1.0d;
            while (iIndexOf2 != -1) {
                dArr3[i7] = Double.parseDouble(str.substring(iIndexOf, iIndexOf2).trim());
                iIndexOf = iIndexOf2 + 1;
                iIndexOf2 = str.indexOf(44, iIndexOf);
                i7++;
            }
            dArr3[i7] = Double.parseDouble(str.substring(iIndexOf, str.indexOf(41, iIndexOf)).trim());
            double[] dArrCopyOf = Arrays.copyOf(dArr3, i7 + 1);
            int length = (dArrCopyOf.length * 3) - 2;
            int length2 = dArrCopyOf.length - 1;
            double d2 = 1.0d / length2;
            double[][] dArr4 = (double[][]) Array.newInstance((Class<?>) cls, length, 1);
            double[] dArr5 = new double[length];
            i = 2;
            int i8 = 0;
            while (i8 < dArrCopyOf.length) {
                double d3 = dArrCopyOf[i8];
                int i9 = i8 + length2;
                dArr4[i9][0] = d3;
                double d4 = d2;
                double d5 = i8 * d4;
                dArr5[i9] = d5;
                if (i8 > 0) {
                    int i10 = (length2 * 2) + i8;
                    dArr4[i10][0] = d3 + 1.0d;
                    dArr5[i10] = d5 + 1.0d;
                    int i11 = i8 - 1;
                    dArr4[i11][0] = (d3 - 1.0d) - d4;
                    dArr5[i11] = (d5 - 1.0d) - d4;
                }
                i8++;
                d2 = d4;
            }
            aVar.f = new androidx.constraintlayout.core.motion.utils.h(dArr5, dArr4);
        } else {
            i = 2;
            i2 = 1;
            i3 = 3;
            i4 = 0;
            d = 1.0d;
        }
        v.c = new float[size];
        v.d = new double[size];
        v.e = new float[size];
        v.f = new float[size];
        v.g = new float[size];
        float[] fArr = new float[size];
        this.a = v;
        Iterator it2 = arrayList.iterator();
        int i12 = i4;
        while (it2.hasNext()) {
            ((androidx.constraintlayout.core.motion.utils.f) it2.next()).getClass();
            dArr[i12] = DefinitionKt.NO_Float_VALUE * 0.01d;
            double[] dArr6 = dArr2[i12];
            dArr6[i4] = DefinitionKt.NO_Float_VALUE;
            dArr6[i2] = DefinitionKt.NO_Float_VALUE;
            dArr6[i] = DefinitionKt.NO_Float_VALUE;
            V v2 = this.a;
            ((double[]) v2.d)[i12] = 0 / 100.0d;
            ((float[]) v2.e)[i12] = 0.0f;
            ((float[]) v2.f)[i12] = 0.0f;
            ((float[]) v2.g)[i12] = 0.0f;
            ((float[]) v2.c)[i12] = 0.0f;
            i12++;
        }
        V v3 = this.a;
        double[] dArr7 = (double[]) v3.d;
        int length3 = dArr7.length;
        int i13 = i;
        int[] iArr = new int[i13];
        iArr[i2] = i3;
        iArr[i4] = length3;
        double[][] dArr8 = (double[][]) Array.newInstance((Class<?>) cls, iArr);
        float[] fArr2 = (float[]) v3.c;
        v3.i = new double[fArr2.length + i13];
        double[] dArr9 = new double[fArr2.length + i13];
        double d6 = dArr7[i4];
        double d7 = 0.0d;
        float[] fArr3 = (float[]) v3.e;
        androidx.camera.camera2.internal.concurrent.a aVar2 = (androidx.camera.camera2.internal.concurrent.a) v3.b;
        if (d6 > 0.0d) {
            aVar2.a(0.0d, fArr3[i4]);
        }
        int length4 = dArr7.length - 1;
        if (dArr7[length4] < d) {
            aVar2.a(d, fArr3[length4]);
        }
        for (int i14 = i4; i14 < dArr8.length; i14++) {
            double[] dArr10 = dArr8[i14];
            dArr10[i4] = ((float[]) v3.f)[i14];
            dArr10[i2] = ((float[]) v3.g)[i14];
            dArr10[2] = fArr2[i14];
            aVar2.a(dArr7[i14], fArr3[i14]);
        }
        double d8 = 0.0d;
        int i15 = i4;
        while (true) {
            if (i15 >= ((float[]) aVar2.c).length) {
                break;
            }
            d8 += r12[i15];
            i15++;
        }
        double d9 = 0.0d;
        int i16 = i2;
        while (true) {
            float[] fArr4 = (float[]) aVar2.c;
            if (i16 >= fArr4.length) {
                break;
            }
            int i17 = i16 - 1;
            float f = (fArr4[i17] + fArr4[i16]) / 2.0f;
            double d10 = d7;
            double[] dArr11 = (double[]) aVar2.d;
            d9 = ((dArr11[i16] - dArr11[i17]) * f) + d9;
            i16++;
            d7 = d10;
        }
        double d11 = d7;
        int i18 = i4;
        while (true) {
            float[] fArr5 = (float[]) aVar2.c;
            if (i18 >= fArr5.length) {
                break;
            }
            fArr5[i18] = fArr5[i18] * ((float) (d8 / d9));
            i18++;
        }
        ((double[]) aVar2.e)[i4] = d11;
        int i19 = i2;
        while (true) {
            float[] fArr6 = (float[]) aVar2.c;
            if (i19 >= fArr6.length) {
                break;
            }
            int i20 = i19 - 1;
            float f2 = (fArr6[i20] + fArr6[i19]) / 2.0f;
            double[] dArr12 = (double[]) aVar2.d;
            double d12 = dArr12[i19] - dArr12[i20];
            double[] dArr13 = (double[]) aVar2.e;
            double d13 = dArr13[i20];
            int i21 = i19;
            dArr13[i21] = (d12 * f2) + d13;
            i19 = i21 + 1;
        }
        if (dArr7.length > i2) {
            i5 = i4;
            v3.h = AbstractC3107b6.b(i5, dArr7, dArr8);
        } else {
            i5 = i4;
            v3.h = null;
        }
        AbstractC3107b6.b(i5, dArr, dArr2);
    }

    public final String toString() {
        String string = this.b;
        DecimalFormat decimalFormat = new DecimalFormat("##.##");
        Iterator it2 = this.f.iterator();
        while (it2.hasNext()) {
            androidx.constraintlayout.core.motion.utils.f fVar = (androidx.constraintlayout.core.motion.utils.f) it2.next();
            StringBuilder sbX = android.support.v4.media.session.a.x(string, "[");
            fVar.getClass();
            sbX.append(0);
            sbX.append(" , ");
            sbX.append(decimalFormat.format(DefinitionKt.NO_Float_VALUE));
            sbX.append("] ");
            string = sbX.toString();
        }
        return string;
    }
}

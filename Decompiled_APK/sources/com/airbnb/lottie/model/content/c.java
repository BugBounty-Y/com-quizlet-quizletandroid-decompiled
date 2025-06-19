package com.airbnb.lottie.model.content;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3532t;
import java.util.Arrays;

/* loaded from: classes.dex */
public final class c {
    public final float[] a;
    public final int[] b;

    public c(float[] fArr, int[] iArr) {
        this.a = fArr;
        this.b = iArr;
    }

    public final void a(c cVar) {
        int i = 0;
        while (true) {
            int[] iArr = cVar.b;
            if (i >= iArr.length) {
                return;
            }
            this.a[i] = cVar.a[i];
            this.b[i] = iArr[i];
            i++;
        }
    }

    public final c b(float[] fArr) {
        int iC;
        int[] iArr = new int[fArr.length];
        for (int i = 0; i < fArr.length; i++) {
            float f = fArr[i];
            float[] fArr2 = this.a;
            int iBinarySearch = Arrays.binarySearch(fArr2, f);
            int[] iArr2 = this.b;
            if (iBinarySearch >= 0) {
                iC = iArr2[iBinarySearch];
            } else {
                int i2 = -(iBinarySearch + 1);
                if (i2 == 0) {
                    iC = iArr2[0];
                } else if (i2 == iArr2.length - 1) {
                    iC = iArr2[iArr2.length - 1];
                } else {
                    int i3 = i2 - 1;
                    float f2 = fArr2[i3];
                    iC = AbstractC3532t.c(iArr2[i3], (f - f2) / (fArr2[i2] - f2), iArr2[i2]);
                }
            }
            iArr[i] = iC;
        }
        return new c(fArr, iArr);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && c.class == obj.getClass()) {
            c cVar = (c) obj;
            if (Arrays.equals(this.a, cVar.a) && Arrays.equals(this.b, cVar.b)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return Arrays.hashCode(this.b) + (Arrays.hashCode(this.a) * 31);
    }
}

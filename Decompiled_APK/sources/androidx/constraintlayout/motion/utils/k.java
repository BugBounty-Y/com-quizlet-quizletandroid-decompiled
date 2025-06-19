package androidx.constraintlayout.motion.utils;

import android.view.View;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3107b6;
import java.text.DecimalFormat;
import java.util.Arrays;

/* loaded from: classes.dex */
public abstract class k {
    public AbstractC3107b6 a;
    public int[] b = new int[10];
    public float[] c = new float[10];
    public int d;
    public String e;

    public final float a(float f) {
        return (float) this.a.c(f);
    }

    public void b(float f, int i) {
        int[] iArr = this.b;
        if (iArr.length < this.d + 1) {
            this.b = Arrays.copyOf(iArr, iArr.length * 2);
            float[] fArr = this.c;
            this.c = Arrays.copyOf(fArr, fArr.length * 2);
        }
        int[] iArr2 = this.b;
        int i2 = this.d;
        iArr2[i2] = i;
        this.c[i2] = f;
        this.d = i2 + 1;
    }

    public abstract void c(View view, float f);

    /* JADX WARN: Removed duplicated region for block: B:31:0x009d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void d(int r18) {
        /*
            Method dump skipped, instructions count: 193
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.motion.utils.k.d(int):void");
    }

    public final String toString() {
        String string = this.e;
        DecimalFormat decimalFormat = new DecimalFormat("##.##");
        for (int i = 0; i < this.d; i++) {
            StringBuilder sbX = android.support.v4.media.session.a.x(string, "[");
            sbX.append(this.b[i]);
            sbX.append(" , ");
            sbX.append(decimalFormat.format(this.c[i]));
            sbX.append("] ");
            string = sbX.toString();
        }
        return string;
    }
}

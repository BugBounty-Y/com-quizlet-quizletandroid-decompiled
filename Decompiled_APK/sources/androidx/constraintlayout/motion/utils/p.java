package androidx.constraintlayout.motion.utils;

import android.view.View;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3107b6;
import com.skydoves.balloon.internals.DefinitionKt;
import java.lang.reflect.Array;
import java.text.DecimalFormat;
import java.util.Arrays;
import java.util.HashMap;

/* loaded from: classes.dex */
public abstract class p {
    public AbstractC3107b6 a;
    public String e;
    public long h;
    public int b = 0;
    public int[] c = new int[10];
    public float[][] d = (float[][]) Array.newInstance((Class<?>) Float.TYPE, 10, 3);
    public float[] f = new float[3];
    public boolean g = false;
    public float i = Float.NaN;

    public final float a(float f) {
        float fAbs;
        switch (this.b) {
            case 1:
                return Math.signum(f * 6.2831855f);
            case 2:
                fAbs = Math.abs(f);
                break;
            case 3:
                return (((f * 2.0f) + 1.0f) % 2.0f) - 1.0f;
            case 4:
                fAbs = ((f * 2.0f) + 1.0f) % 2.0f;
                break;
            case 5:
                return (float) Math.cos(f * 6.2831855f);
            case 6:
                float fAbs2 = 1.0f - Math.abs(((f * 4.0f) % 4.0f) - 2.0f);
                fAbs = fAbs2 * fAbs2;
                break;
            default:
                return (float) Math.sin(f * 6.2831855f);
        }
        return 1.0f - fAbs;
    }

    public final float b(float f, long j, View view, androidx.constraintlayout.core.motion.utils.e eVar) {
        this.a.e(f, this.f);
        float[] fArr = this.f;
        boolean z = true;
        float f2 = fArr[1];
        if (f2 == DefinitionKt.NO_Float_VALUE) {
            this.g = false;
            return fArr[2];
        }
        if (Float.isNaN(this.i)) {
            float fC = eVar.c(view, this.e);
            this.i = fC;
            if (Float.isNaN(fC)) {
                this.i = DefinitionKt.NO_Float_VALUE;
            }
        }
        float f3 = (float) (((((j - this.h) * 1.0E-9d) * f2) + this.i) % 1.0d);
        this.i = f3;
        String str = this.e;
        HashMap map = (HashMap) eVar.b;
        if (map.containsKey(view)) {
            HashMap map2 = (HashMap) map.get(view);
            if (map2 == null) {
                map2 = new HashMap();
            }
            if (map2.containsKey(str)) {
                float[] fArrCopyOf = (float[]) map2.get(str);
                if (fArrCopyOf == null) {
                    fArrCopyOf = new float[0];
                }
                if (fArrCopyOf.length <= 0) {
                    fArrCopyOf = Arrays.copyOf(fArrCopyOf, 1);
                }
                fArrCopyOf[0] = f3;
                map2.put(str, fArrCopyOf);
            } else {
                map2.put(str, new float[]{f3});
                map.put(view, map2);
            }
        } else {
            HashMap map3 = new HashMap();
            map3.put(str, new float[]{f3});
            map.put(view, map3);
        }
        this.h = j;
        float f4 = this.f[0];
        float fA = (a(this.i) * f4) + this.f[2];
        if (f4 == DefinitionKt.NO_Float_VALUE && f2 == DefinitionKt.NO_Float_VALUE) {
            z = false;
        }
        this.g = z;
        return fA;
    }

    public abstract boolean c(float f, long j, View view, androidx.constraintlayout.core.motion.utils.e eVar);

    public void d(int i) {
        System.err.println("Error no points added to " + this.e);
    }

    public final String toString() {
        String string = this.e;
        DecimalFormat decimalFormat = new DecimalFormat("##.##");
        for (int i = 0; i < 0; i++) {
            StringBuilder sbX = android.support.v4.media.session.a.x(string, "[");
            sbX.append(this.c[i]);
            sbX.append(" , ");
            sbX.append(decimalFormat.format(this.d[i]));
            sbX.append("] ");
            string = sbX.toString();
        }
        return string;
    }
}

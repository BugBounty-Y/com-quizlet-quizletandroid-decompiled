package androidx.constraintlayout.core.motion.utils;

import android.view.View;
import java.io.Serializable;
import java.util.HashMap;

/* loaded from: classes.dex */
public class e {
    public static final e c = new e(0);
    public static final String[] d = {"standard", "accelerate", "decelerate", "linear"};
    public final /* synthetic */ int a;
    public Serializable b;

    public e(int i) {
        this.a = i;
        switch (i) {
            case 1:
                this.b = new HashMap();
                break;
            default:
                this.b = "identity";
                break;
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:30:0x0143  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static androidx.constraintlayout.core.motion.utils.e d(java.lang.String r21) {
        /*
            Method dump skipped, instructions count: 510
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.motion.utils.e.d(java.lang.String):androidx.constraintlayout.core.motion.utils.e");
    }

    public double a(double d2) {
        return d2;
    }

    public double b(double d2) {
        return 1.0d;
    }

    public float c(View view, String str) {
        HashMap map;
        float[] fArr;
        HashMap map2 = (HashMap) this.b;
        if (map2.containsKey(view) && (map = (HashMap) map2.get(view)) != null && map.containsKey(str) && (fArr = (float[]) map.get(str)) != null && fArr.length > 0) {
            return fArr[0];
        }
        return Float.NaN;
    }

    public String toString() {
        switch (this.a) {
            case 0:
                return (String) this.b;
            default:
                return super.toString();
        }
    }
}

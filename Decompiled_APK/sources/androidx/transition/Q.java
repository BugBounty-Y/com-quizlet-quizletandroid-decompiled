package androidx.transition;

import android.graphics.Matrix;
import android.os.Build;
import android.view.View;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3371n2;

/* loaded from: classes.dex */
public class Q extends AbstractC3371n2 {
    public static boolean e = true;
    public static boolean f = true;
    public static boolean g = true;
    public static boolean h = true;

    @Override // com.google.android.gms.internal.mlkit_vision_camera.AbstractC3371n2
    public void d(View view, int i) throws IllegalAccessException, NoSuchFieldException, SecurityException, IllegalArgumentException {
        if (Build.VERSION.SDK_INT == 28) {
            super.d(view, i);
        } else if (h) {
            try {
                P.a(view, i);
            } catch (NoSuchMethodError unused) {
                h = false;
            }
        }
    }

    public void e(View view, int i, int i2, int i3, int i4) {
        if (g) {
            try {
                O.a(view, i, i2, i3, i4);
            } catch (NoSuchMethodError unused) {
                g = false;
            }
        }
    }

    public void f(View view, Matrix matrix) {
        if (e) {
            try {
                N.b(view, matrix);
            } catch (NoSuchMethodError unused) {
                e = false;
            }
        }
    }

    public void g(View view, Matrix matrix) {
        if (f) {
            try {
                N.c(view, matrix);
            } catch (NoSuchMethodError unused) {
                f = false;
            }
        }
    }
}

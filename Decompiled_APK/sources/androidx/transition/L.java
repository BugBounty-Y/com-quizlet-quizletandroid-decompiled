package androidx.transition;

import android.graphics.Rect;
import android.os.Build;
import android.view.View;
import androidx.appcompat.widget.k1;

/* loaded from: classes.dex */
public abstract class L {
    public static final Q a;
    public static final k1 b;

    static {
        if (Build.VERSION.SDK_INT >= 29) {
            a = new S();
        } else {
            a = new Q();
        }
        b = new k1(6, Float.class, "translationAlpha");
        new k1(7, Rect.class, "clipBounds");
    }

    public static void a(View view, int i, int i2, int i3, int i4) {
        a.e(view, i, i2, i3, i4);
    }

    public static void b(View view, int i) throws IllegalAccessException, NoSuchFieldException, SecurityException, IllegalArgumentException {
        a.d(view, i);
    }
}

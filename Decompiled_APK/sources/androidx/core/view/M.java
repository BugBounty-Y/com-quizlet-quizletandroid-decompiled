package androidx.core.view;

import android.view.View;
import android.view.WindowInsets;

/* loaded from: classes.dex */
public abstract class M {
    public static D0 a(View view) {
        WindowInsets rootWindowInsets = view.getRootWindowInsets();
        if (rootWindowInsets == null) {
            return null;
        }
        D0 d0H = D0.h(null, rootWindowInsets);
        z0 z0Var = d0H.a;
        z0Var.t(d0H);
        z0Var.d(view.getRootView());
        return d0H;
    }

    public static void b(View view, int i, int i2) {
        view.setScrollIndicators(i, i2);
    }
}

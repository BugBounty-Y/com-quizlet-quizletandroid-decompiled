package androidx.core.view;

import android.view.View;
import android.view.WindowInsets;

/* loaded from: classes.dex */
public abstract class J {
    public static WindowInsets a(View view, WindowInsets windowInsets) {
        int i = W.a;
        return view.dispatchApplyWindowInsets(windowInsets);
    }

    public static WindowInsets b(View view, WindowInsets windowInsets) {
        return view.onApplyWindowInsets(windowInsets);
    }

    public static void c(View view) {
        view.requestApplyInsets();
    }
}

package androidx.transition;

import android.view.View;

/* loaded from: classes.dex */
public abstract class M {
    public static float a(View view) {
        return view.getTransitionAlpha();
    }

    public static void b(View view, float f) {
        view.setTransitionAlpha(f);
    }
}

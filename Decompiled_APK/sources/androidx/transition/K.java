package androidx.transition;

import android.view.ViewGroup;

/* loaded from: classes.dex */
public abstract class K {
    public static int a(ViewGroup viewGroup, int i) {
        return viewGroup.getChildDrawingOrder(i);
    }

    public static void b(ViewGroup viewGroup, boolean z) {
        viewGroup.suppressLayout(z);
    }
}

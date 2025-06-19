package androidx.compose.ui.platform;

import android.view.View;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class M {
    public static final M a = new M();

    public final void a(@NotNull View view, int i, boolean z) {
        view.setFocusable(i);
        view.setDefaultFocusHighlightEnabled(z);
    }
}

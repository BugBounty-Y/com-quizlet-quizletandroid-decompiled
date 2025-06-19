package androidx.compose.ui.platform;

import android.view.View;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class K {
    public static final K a = new K();

    public final void a(@NotNull View view) {
        view.clearViewTranslationCallback();
    }

    public final void b(@NotNull View view) {
        J j = J.a;
        J j2 = J.a;
        view.setViewTranslationCallback(J.a);
    }
}

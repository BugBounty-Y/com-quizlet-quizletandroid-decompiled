package androidx.compose.ui.platform;

import android.view.View;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class c1 {
    public static final c1 a = new c1();

    public final void a(@NotNull View view, int i) {
        view.setOutlineAmbientShadowColor(i);
    }

    public final void b(@NotNull View view, int i) {
        view.setOutlineSpotShadowColor(i);
    }
}

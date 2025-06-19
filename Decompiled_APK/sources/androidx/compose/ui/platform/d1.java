package androidx.compose.ui.platform;

import android.view.View;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class d1 {
    public static final d1 a = new d1();

    public final void a(@NotNull View view, androidx.compose.ui.graphics.P p) {
        view.setRenderEffect(p != null ? p.a() : null);
    }
}

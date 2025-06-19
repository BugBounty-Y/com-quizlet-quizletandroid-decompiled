package androidx.compose.ui.text.android;

import android.text.StaticLayout;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public abstract class q {
    public static final void a(@NotNull StaticLayout.Builder builder, boolean z) {
        builder.setUseLineSpacingFromFallbacks(z);
    }
}

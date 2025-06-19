package androidx.compose.ui.text.android;

import android.text.StaticLayout;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public abstract class r {
    public static final boolean a(@NotNull StaticLayout staticLayout) {
        return staticLayout.isFallbackLineSpacingEnabled();
    }

    public static final void b(@NotNull StaticLayout.Builder builder, int i, int i2) {
        builder.setLineBreakConfig(androidx.activity.t.f().setLineBreakStyle(i).setLineBreakWordStyle(i2).build());
    }
}

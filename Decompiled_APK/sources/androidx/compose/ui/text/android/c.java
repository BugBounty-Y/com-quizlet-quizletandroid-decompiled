package androidx.compose.ui.text.android;

import android.text.BoringLayout;
import android.text.Layout;
import android.text.TextDirectionHeuristic;
import android.text.TextPaint;
import android.text.TextUtils;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public abstract class c {
    @NotNull
    public static final BoringLayout a(@NotNull CharSequence charSequence, @NotNull TextPaint textPaint, int i, @NotNull Layout.Alignment alignment, float f, float f2, @NotNull BoringLayout.Metrics metrics, boolean z, boolean z2, TextUtils.TruncateAt truncateAt, int i2) {
        return androidx.activity.t.l(charSequence, textPaint, i, alignment, f, f2, metrics, z, z2, truncateAt, i2);
    }

    public static final BoringLayout.Metrics b(@NotNull CharSequence charSequence, @NotNull TextPaint textPaint, @NotNull TextDirectionHeuristic textDirectionHeuristic) {
        return BoringLayout.isBoring(charSequence, textPaint, textDirectionHeuristic, true, null);
    }

    public static final boolean c(@NotNull BoringLayout boringLayout) {
        return boringLayout.isFallbackLineSpacingEnabled();
    }
}

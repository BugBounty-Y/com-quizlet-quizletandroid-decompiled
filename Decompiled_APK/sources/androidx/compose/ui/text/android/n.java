package androidx.compose.ui.text.android;

import android.graphics.Paint;
import android.graphics.Rect;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public abstract class n {
    public static final void a(@NotNull Paint paint, @NotNull CharSequence charSequence, int i, int i2, @NotNull Rect rect) {
        paint.getTextBounds(charSequence, i, i2, rect);
    }
}

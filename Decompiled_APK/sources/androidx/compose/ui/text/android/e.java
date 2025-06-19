package androidx.compose.ui.text.android;

import android.graphics.Canvas;
import android.graphics.Paint;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class e {
    public static final e a = new e();

    public final void a(@NotNull Canvas canvas, @NotNull CharSequence charSequence, int i, int i2, int i3, int i4, float f, float f2, boolean z, @NotNull Paint paint) {
        canvas.drawTextRun(charSequence, i, i2, i3, i4, f, f2, z, paint);
    }

    public final void b(@NotNull Canvas canvas, @NotNull char[] cArr, int i, int i2, int i3, int i4, float f, float f2, boolean z, @NotNull Paint paint) {
        canvas.drawTextRun(cArr, i, i2, i3, i4, f, f2, z, paint);
    }
}

package androidx.compose.ui.text.android;

import android.graphics.Canvas;
import android.graphics.NinePatch;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.fonts.Font;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class i {
    public static final i a = new i();

    public final void a(@NotNull Canvas canvas, @NotNull int[] iArr, int i, @NotNull float[] fArr, int i2, int i3, @NotNull Font font, @NotNull Paint paint) {
        canvas.drawGlyphs(iArr, i, fArr, i2, i3, font, paint);
    }

    public final void b(@NotNull Canvas canvas, @NotNull NinePatch ninePatch, @NotNull Rect rect, Paint paint) {
        canvas.drawPatch(ninePatch, rect, paint);
    }

    public final void c(@NotNull Canvas canvas, @NotNull NinePatch ninePatch, @NotNull RectF rectF, Paint paint) {
        canvas.drawPatch(ninePatch, rectF, paint);
    }
}

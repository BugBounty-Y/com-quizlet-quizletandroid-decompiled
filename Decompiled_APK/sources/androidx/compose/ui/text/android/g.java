package androidx.compose.ui.text.android;

import android.graphics.BlendMode;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.RenderNode;
import android.graphics.text.MeasuredText;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class g {
    public static final g a = new g();

    public final void a(@NotNull Canvas canvas) {
        canvas.disableZ();
    }

    public final void b(@NotNull Canvas canvas, int i, @NotNull BlendMode blendMode) {
        canvas.drawColor(i, blendMode);
    }

    public final void c(@NotNull Canvas canvas, long j) {
        canvas.drawColor(j);
    }

    public final void d(@NotNull Canvas canvas, long j, @NotNull BlendMode blendMode) {
        canvas.drawColor(j, blendMode);
    }

    public final void e(@NotNull Canvas canvas, @NotNull RectF rectF, float f, float f2, @NotNull RectF rectF2, float f3, float f4, @NotNull Paint paint) {
        canvas.drawDoubleRoundRect(rectF, f, f2, rectF2, f3, f4, paint);
    }

    public final void f(@NotNull Canvas canvas, @NotNull RectF rectF, @NotNull float[] fArr, @NotNull RectF rectF2, @NotNull float[] fArr2, @NotNull Paint paint) {
        canvas.drawDoubleRoundRect(rectF, fArr, rectF2, fArr2, paint);
    }

    public final void g(@NotNull Canvas canvas, @NotNull RenderNode renderNode) {
        canvas.drawRenderNode(renderNode);
    }

    public final void h(@NotNull Canvas canvas, @NotNull MeasuredText measuredText, int i, int i2, int i3, int i4, float f, float f2, boolean z, @NotNull Paint paint) {
        canvas.drawTextRun(measuredText, i, i2, i3, i4, f, f2, z, paint);
    }

    public final void i(@NotNull Canvas canvas) {
        canvas.enableZ();
    }
}

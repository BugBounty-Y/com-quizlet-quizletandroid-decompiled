package androidx.compose.ui.text.android;

import android.graphics.Canvas;
import android.graphics.Path;
import android.graphics.RectF;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class h {
    public static final h a = new h();

    public final boolean a(@NotNull Canvas canvas, float f, float f2, float f3, float f4) {
        return canvas.quickReject(f, f2, f3, f4);
    }

    public final boolean b(@NotNull Canvas canvas, @NotNull Path path) {
        return canvas.quickReject(path);
    }

    public final boolean c(@NotNull Canvas canvas, @NotNull RectF rectF) {
        return canvas.quickReject(rectF);
    }
}

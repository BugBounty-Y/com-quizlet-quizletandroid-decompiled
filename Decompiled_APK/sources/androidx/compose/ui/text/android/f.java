package androidx.compose.ui.text.android;

import android.graphics.Canvas;
import android.graphics.Path;
import android.graphics.Rect;
import android.graphics.RectF;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class f {
    public static final f a = new f();

    public final boolean a(@NotNull Canvas canvas, @NotNull Path path) {
        return canvas.clipOutPath(path);
    }

    public final boolean b(@NotNull Canvas canvas, float f, float f2, float f3, float f4) {
        return canvas.clipOutRect(f, f2, f3, f4);
    }

    public final boolean c(@NotNull Canvas canvas, int i, int i2, int i3, int i4) {
        return canvas.clipOutRect(i, i2, i3, i4);
    }

    public final boolean d(@NotNull Canvas canvas, @NotNull Rect rect) {
        return canvas.clipOutRect(rect);
    }

    public final boolean e(@NotNull Canvas canvas, @NotNull RectF rectF) {
        return canvas.clipOutRect(rectF);
    }
}

package androidx.compose.ui.graphics;

import android.graphics.ColorMatrix;
import android.graphics.ColorMatrixColorFilter;
import org.jetbrains.annotations.NotNull;

/* renamed from: androidx.compose.ui.graphics.y, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0876y {
    public static final C0876y a = new C0876y();

    @NotNull
    public final float[] a(@NotNull ColorMatrixColorFilter colorMatrixColorFilter) {
        ColorMatrix colorMatrix = new ColorMatrix();
        colorMatrixColorFilter.getColorMatrix(colorMatrix);
        return colorMatrix.getArray();
    }
}

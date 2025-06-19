package androidx.compose.ui.graphics;

import android.graphics.Bitmap;
import android.graphics.ColorSpace;
import android.util.DisplayMetrics;
import org.jetbrains.annotations.NotNull;

/* renamed from: androidx.compose.ui.graphics.l, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0852l {
    @NotNull
    public static final androidx.compose.ui.graphics.colorspace.c a(@NotNull Bitmap bitmap) {
        androidx.compose.ui.graphics.colorspace.c cVarB;
        ColorSpace colorSpace = bitmap.getColorSpace();
        return (colorSpace == null || (cVarB = C.b(colorSpace)) == null) ? androidx.compose.ui.graphics.colorspace.d.c : cVarB;
    }

    @NotNull
    public static final Bitmap b(int i, int i2, int i3, boolean z, @NotNull androidx.compose.ui.graphics.colorspace.c cVar) {
        return Bitmap.createBitmap((DisplayMetrics) null, i, i2, F.B(i3), z, C.a(cVar));
    }
}

package androidx.compose.ui.text.font;

import android.graphics.Typeface;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class D {
    public static final D a = new D();

    @NotNull
    public final Typeface a(@NotNull Typeface typeface, int i, boolean z) {
        return Typeface.create(typeface, i, z);
    }
}

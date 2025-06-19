package androidx.compose.ui.platform;

import android.view.View;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public abstract class Z0 {
    public static final long a(@NotNull View view) {
        return view.getUniqueDrawingId();
    }
}

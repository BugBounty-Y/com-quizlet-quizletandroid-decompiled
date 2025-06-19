package androidx.compose.ui.graphics.layer;

import android.graphics.Outline;
import androidx.compose.ui.graphics.C0850j;
import androidx.compose.ui.graphics.O;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class k {
    public static final k a = new k();

    public final void a(@NotNull Outline outline, @NotNull O o) {
        if (!(o instanceof C0850j)) {
            throw new UnsupportedOperationException("Unable to obtain android.graphics.Path");
        }
        outline.setPath(((C0850j) o).a);
    }
}

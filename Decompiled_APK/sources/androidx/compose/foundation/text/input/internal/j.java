package androidx.compose.foundation.text.input.internal;

import android.view.inputmethod.CursorAnchorInfo;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public abstract class j {
    @NotNull
    public static final CursorAnchorInfo.Builder a(@NotNull CursorAnchorInfo.Builder builder, @NotNull androidx.compose.ui.geometry.c cVar) {
        return builder.setEditorBoundsInfo(androidx.activity.t.o().setEditorBounds(androidx.compose.ui.graphics.F.y(cVar)).setHandwritingBounds(androidx.compose.ui.graphics.F.y(cVar)).build());
    }
}

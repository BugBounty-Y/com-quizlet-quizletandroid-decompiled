package androidx.compose.ui.text.input;

import android.view.inputmethod.CursorAnchorInfo;
import org.jetbrains.annotations.NotNull;

/* renamed from: androidx.compose.ui.text.input.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0999b {
    @NotNull
    public static final CursorAnchorInfo.Builder a(@NotNull CursorAnchorInfo.Builder builder, @NotNull androidx.compose.ui.geometry.c cVar) {
        return builder.setEditorBoundsInfo(androidx.activity.t.o().setEditorBounds(androidx.compose.ui.graphics.F.y(cVar)).setHandwritingBounds(androidx.compose.ui.graphics.F.y(cVar)).build());
    }
}

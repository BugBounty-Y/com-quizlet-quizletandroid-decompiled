package androidx.compose.foundation.text.input.internal;

import android.view.inputmethod.CursorAnchorInfo;
import androidx.compose.ui.text.H;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public abstract class k {
    @NotNull
    public static final CursorAnchorInfo.Builder a(@NotNull CursorAnchorInfo.Builder builder, @NotNull H h, @NotNull androidx.compose.ui.geometry.c cVar) {
        int iC;
        androidx.compose.ui.text.o oVar;
        int iC2;
        if (!cVar.g() && (iC = h.b.c(cVar.b)) <= (iC2 = (oVar = h.b).c(cVar.d))) {
            while (true) {
                builder.addVisibleLineBounds(h.g(iC), oVar.d(iC), h.h(iC), oVar.b(iC));
                if (iC == iC2) {
                    break;
                }
                iC++;
            }
        }
        return builder;
    }
}

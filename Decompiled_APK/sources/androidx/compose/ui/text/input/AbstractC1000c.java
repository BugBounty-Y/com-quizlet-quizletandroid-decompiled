package androidx.compose.ui.text.input;

import android.view.inputmethod.CursorAnchorInfo;
import org.jetbrains.annotations.NotNull;

/* renamed from: androidx.compose.ui.text.input.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC1000c {
    @NotNull
    public static final CursorAnchorInfo.Builder a(@NotNull CursorAnchorInfo.Builder builder, @NotNull androidx.compose.ui.text.H h, @NotNull androidx.compose.ui.geometry.c cVar) {
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

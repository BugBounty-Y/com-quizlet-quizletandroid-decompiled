package androidx.compose.ui.graphics;

import android.graphics.Canvas;
import org.jetbrains.annotations.NotNull;

/* renamed from: androidx.compose.ui.graphics.u, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0860u {
    public static final C0860u a = new C0860u();

    public final void a(@NotNull Canvas canvas, boolean z) {
        if (z) {
            canvas.enableZ();
        } else {
            canvas.disableZ();
        }
    }
}

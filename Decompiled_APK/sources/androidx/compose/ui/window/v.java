package androidx.compose.ui.window;

import android.graphics.Rect;
import kotlin.collections.B;

/* loaded from: classes.dex */
public final class v extends w {
    @Override // androidx.compose.ui.window.w
    public final void a(u uVar, int i, int i2) {
        uVar.setSystemGestureExclusionRects(B.k(new Rect(0, 0, i, i2)));
    }
}

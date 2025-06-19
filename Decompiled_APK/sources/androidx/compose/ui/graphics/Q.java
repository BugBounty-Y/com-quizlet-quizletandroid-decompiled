package androidx.compose.ui.graphics;

import android.graphics.RenderEffect;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class Q {
    public static final Q a = new Q();

    @NotNull
    public final RenderEffect a(P p, float f, float f2, int i) {
        return p == null ? RenderEffect.createBlurEffect(f, f2, F.z(i)) : RenderEffect.createBlurEffect(f, f2, p.a(), F.z(i));
    }

    @NotNull
    public final RenderEffect b(P p, long j) {
        return p == null ? RenderEffect.createOffsetEffect(androidx.compose.ui.geometry.b.d(j), androidx.compose.ui.geometry.b.e(j)) : RenderEffect.createOffsetEffect(androidx.compose.ui.geometry.b.d(j), androidx.compose.ui.geometry.b.e(j), p.a());
    }
}

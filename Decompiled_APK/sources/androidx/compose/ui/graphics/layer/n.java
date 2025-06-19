package androidx.compose.ui.graphics.layer;

import android.graphics.RenderNode;
import androidx.compose.ui.graphics.P;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class n {
    public static final n a = new n();

    public final void a(@NotNull RenderNode renderNode, P p) {
        renderNode.setRenderEffect(p != null ? p.a() : null);
    }
}

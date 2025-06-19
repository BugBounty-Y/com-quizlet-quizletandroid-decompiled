package androidx.compose.ui.platform;

import android.graphics.RenderNode;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class J0 {
    public static final J0 a = new J0();

    public final void a(@NotNull RenderNode renderNode, androidx.compose.ui.graphics.P p) {
        renderNode.setRenderEffect(p != null ? p.a() : null);
    }
}

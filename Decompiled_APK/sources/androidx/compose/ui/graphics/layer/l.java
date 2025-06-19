package androidx.compose.ui.graphics.layer;

import android.view.RenderNode;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class l {
    public static final l a = new l();

    public final void a(@NotNull RenderNode renderNode) {
        renderNode.discardDisplayList();
    }
}

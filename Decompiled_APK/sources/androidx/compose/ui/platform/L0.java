package androidx.compose.ui.platform;

import android.view.RenderNode;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class L0 {
    public static final L0 a = new L0();

    public final void a(@NotNull RenderNode renderNode) {
        renderNode.discardDisplayList();
    }
}

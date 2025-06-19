package androidx.compose.ui.platform;

import android.view.RenderNode;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class M0 {
    public static final M0 a = new M0();

    public final int a(@NotNull RenderNode renderNode) {
        return renderNode.getAmbientShadowColor();
    }

    public final int b(@NotNull RenderNode renderNode) {
        return renderNode.getSpotShadowColor();
    }

    public final void c(@NotNull RenderNode renderNode, int i) {
        renderNode.setAmbientShadowColor(i);
    }

    public final void d(@NotNull RenderNode renderNode, int i) {
        renderNode.setSpotShadowColor(i);
    }
}

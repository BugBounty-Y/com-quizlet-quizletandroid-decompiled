package androidx.core.view;

import android.graphics.RenderNode;
import android.view.WindowInsets;

/* loaded from: classes.dex */
public abstract /* synthetic */ class o0 {
    public static /* synthetic */ RenderNode g() {
        return new RenderNode("OffscreenLayer.main");
    }

    public static /* synthetic */ WindowInsets.Builder h(WindowInsets windowInsets) {
        return new WindowInsets.Builder(windowInsets);
    }

    public static /* synthetic */ RenderNode y() {
        return new RenderNode("OffscreenLayer.shadow");
    }
}

package androidx.compose.ui.graphics;

import android.graphics.RenderEffect;

/* loaded from: classes.dex */
public abstract class P {
    public RenderEffect a;

    public final RenderEffect a() {
        RenderEffect renderEffect = this.a;
        if (renderEffect != null) {
            return renderEffect;
        }
        C0856p c0856p = (C0856p) this;
        RenderEffect renderEffectA = Q.a.a(null, c0856p.b, c0856p.c, c0856p.d);
        this.a = renderEffectA;
        return renderEffectA;
    }
}

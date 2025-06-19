package androidx.constraintlayout.motion.widget;

import android.view.animation.Interpolator;

/* loaded from: classes.dex */
public final class i implements Interpolator {
    public final /* synthetic */ androidx.constraintlayout.core.motion.utils.e a;

    public i(androidx.constraintlayout.core.motion.utils.e eVar) {
        this.a = eVar;
    }

    @Override // android.animation.TimeInterpolator
    public final float getInterpolation(float f) {
        return (float) this.a.a(f);
    }
}

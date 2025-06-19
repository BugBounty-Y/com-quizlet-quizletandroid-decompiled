package androidx.core.view;

import android.view.WindowInsetsAnimation;

/* loaded from: classes.dex */
public final class k0 extends l0 {
    public final WindowInsetsAnimation e;

    public k0(WindowInsetsAnimation windowInsetsAnimation) {
        super(0, null, 0L);
        this.e = windowInsetsAnimation;
    }

    @Override // androidx.core.view.l0
    public final long a() {
        return this.e.getDurationMillis();
    }

    @Override // androidx.core.view.l0
    public final float b() {
        return this.e.getInterpolatedFraction();
    }

    @Override // androidx.core.view.l0
    public final int c() {
        return this.e.getTypeMask();
    }

    @Override // androidx.core.view.l0
    public final void d(float f) {
        this.e.setFraction(f);
    }
}

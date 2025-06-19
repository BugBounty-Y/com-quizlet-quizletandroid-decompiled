package androidx.swiperefreshlayout.widget;

import android.view.animation.Animation;
import android.view.animation.Transformation;

/* loaded from: classes.dex */
public final class g extends Animation {
    public final /* synthetic */ int a;
    public final /* synthetic */ SwipeRefreshLayout b;

    public /* synthetic */ g(SwipeRefreshLayout swipeRefreshLayout, int i) {
        this.a = i;
        this.b = swipeRefreshLayout;
    }

    @Override // android.view.animation.Animation
    public final void applyTransformation(float f, Transformation transformation) {
        switch (this.a) {
            case 0:
                this.b.setAnimationProgress(f);
                break;
            case 1:
                this.b.setAnimationProgress(1.0f - f);
                break;
            case 2:
                SwipeRefreshLayout swipeRefreshLayout = this.b;
                int iAbs = swipeRefreshLayout.x - Math.abs(swipeRefreshLayout.w);
                swipeRefreshLayout.setTargetOffsetTopAndBottom((swipeRefreshLayout.v + ((int) ((iAbs - r1) * f))) - swipeRefreshLayout.t.getTop());
                e eVar = swipeRefreshLayout.z;
                float f2 = 1.0f - f;
                d dVar = eVar.a;
                if (f2 != dVar.p) {
                    dVar.p = f2;
                }
                eVar.invalidateSelf();
                break;
            default:
                this.b.k(f);
                break;
        }
    }
}

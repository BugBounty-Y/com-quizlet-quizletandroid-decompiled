package androidx.fragment.app;

import android.content.Context;
import android.content.res.Resources;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.Animation;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.fragment.app.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1127d extends G0 {
    public final C1129e c;

    public C1127d(C1129e animationInfo) {
        Intrinsics.checkNotNullParameter(animationInfo, "animationInfo");
        this.c = animationInfo;
    }

    @Override // androidx.fragment.app.G0
    public final void b(ViewGroup container) {
        Intrinsics.checkNotNullParameter(container, "container");
        C1129e c1129e = this.c;
        H0 h0 = c1129e.a;
        View view = h0.c.mView;
        view.clearAnimation();
        container.endViewTransition(view);
        c1129e.a.c(this);
        if (AbstractC1136h0.N(2)) {
            h0.toString();
        }
    }

    @Override // androidx.fragment.app.G0
    public final void c(ViewGroup container) throws Resources.NotFoundException {
        Intrinsics.checkNotNullParameter(container, "container");
        C1129e c1129e = this.c;
        boolean zA = c1129e.a();
        H0 h0 = c1129e.a;
        if (zA) {
            h0.c(this);
            return;
        }
        Context context = container.getContext();
        View view = h0.c.mView;
        Intrinsics.checkNotNullExpressionValue(context, "context");
        J jB = c1129e.b(context);
        if (jB == null) {
            throw new IllegalStateException("Required value was null.");
        }
        Animation animation = (Animation) jB.a;
        if (animation == null) {
            throw new IllegalStateException("Required value was null.");
        }
        if (h0.a != J0.a) {
            view.startAnimation(animation);
            h0.c(this);
            return;
        }
        container.startViewTransition(view);
        K k = new K(animation, container, view);
        k.setAnimationListener(new AnimationAnimationListenerC1125c(h0, container, view, this));
        view.startAnimation(k);
        if (AbstractC1136h0.N(2)) {
            h0.toString();
        }
    }
}

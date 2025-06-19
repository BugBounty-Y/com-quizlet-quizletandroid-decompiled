package androidx.fragment.app;

import android.view.View;
import android.view.ViewGroup;
import android.view.animation.Animation;
import androidx.camera.camera2.internal.RunnableC0130g;
import java.util.Objects;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.fragment.app.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class AnimationAnimationListenerC1125c implements Animation.AnimationListener {
    public final /* synthetic */ H0 a;
    public final /* synthetic */ ViewGroup b;
    public final /* synthetic */ View c;
    public final /* synthetic */ C1127d d;

    public AnimationAnimationListenerC1125c(H0 h0, ViewGroup viewGroup, View view, C1127d c1127d) {
        this.a = h0;
        this.b = viewGroup;
        this.c = view;
        this.d = c1127d;
    }

    @Override // android.view.animation.Animation.AnimationListener
    public final void onAnimationEnd(Animation animation) {
        Intrinsics.checkNotNullParameter(animation, "animation");
        View view = this.c;
        C1127d c1127d = this.d;
        ViewGroup viewGroup = this.b;
        viewGroup.post(new RunnableC0130g(viewGroup, view, c1127d, 11));
        if (AbstractC1136h0.N(2)) {
            Objects.toString(this.a);
        }
    }

    @Override // android.view.animation.Animation.AnimationListener
    public final void onAnimationRepeat(Animation animation) {
        Intrinsics.checkNotNullParameter(animation, "animation");
    }

    @Override // android.view.animation.Animation.AnimationListener
    public final void onAnimationStart(Animation animation) {
        Intrinsics.checkNotNullParameter(animation, "animation");
        if (AbstractC1136h0.N(2)) {
            Objects.toString(this.a);
        }
    }
}

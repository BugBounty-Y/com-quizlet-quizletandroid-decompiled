package androidx.fragment.app;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.view.View;
import android.view.ViewGroup;
import java.util.Objects;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.fragment.app.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1131f extends AnimatorListenerAdapter {
    public final /* synthetic */ ViewGroup a;
    public final /* synthetic */ View b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ H0 d;
    public final /* synthetic */ C1133g e;

    public C1131f(ViewGroup viewGroup, View view, boolean z, H0 h0, C1133g c1133g) {
        this.a = viewGroup;
        this.b = view;
        this.c = z;
        this.d = h0;
        this.e = c1133g;
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public final void onAnimationEnd(Animator anim) {
        Intrinsics.checkNotNullParameter(anim, "anim");
        ViewGroup viewGroup = this.a;
        View viewToAnimate = this.b;
        viewGroup.endViewTransition(viewToAnimate);
        boolean z = this.c;
        H0 h0 = this.d;
        if (z) {
            J0 j0 = h0.a;
            Intrinsics.checkNotNullExpressionValue(viewToAnimate, "viewToAnimate");
            j0.a(viewToAnimate, viewGroup);
        }
        C1133g c1133g = this.e;
        c1133g.c.a.c(c1133g);
        if (AbstractC1136h0.N(2)) {
            Objects.toString(h0);
        }
    }
}

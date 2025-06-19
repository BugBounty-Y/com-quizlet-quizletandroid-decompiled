package androidx.fragment.app;

import android.animation.AnimatorSet;
import android.content.Context;
import android.content.res.Resources;
import android.os.Build;
import android.view.View;
import android.view.ViewGroup;
import androidx.activity.C0030b;
import java.util.Objects;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.fragment.app.g, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1133g extends G0 {
    public final C1129e c;
    public AnimatorSet d;

    public C1133g(C1129e animatorInfo) {
        Intrinsics.checkNotNullParameter(animatorInfo, "animatorInfo");
        this.c = animatorInfo;
    }

    @Override // androidx.fragment.app.G0
    public final void b(ViewGroup container) {
        Intrinsics.checkNotNullParameter(container, "container");
        AnimatorSet animatorSet = this.d;
        C1129e c1129e = this.c;
        if (animatorSet == null) {
            c1129e.a.c(this);
            return;
        }
        H0 h0 = c1129e.a;
        if (h0.g) {
            C1137i.a.a(animatorSet);
        } else {
            animatorSet.end();
        }
        if (AbstractC1136h0.N(2)) {
            h0.toString();
        }
    }

    @Override // androidx.fragment.app.G0
    public final void c(ViewGroup container) {
        Intrinsics.checkNotNullParameter(container, "container");
        H0 h0 = this.c.a;
        AnimatorSet animatorSet = this.d;
        if (animatorSet == null) {
            h0.c(this);
            return;
        }
        animatorSet.start();
        if (AbstractC1136h0.N(2)) {
            Objects.toString(h0);
        }
    }

    @Override // androidx.fragment.app.G0
    public final void d(C0030b backEvent, ViewGroup container) {
        Intrinsics.checkNotNullParameter(backEvent, "backEvent");
        Intrinsics.checkNotNullParameter(container, "container");
        H0 h0 = this.c.a;
        AnimatorSet animatorSet = this.d;
        if (animatorSet == null) {
            h0.c(this);
            return;
        }
        if (Build.VERSION.SDK_INT < 34 || !h0.c.mTransitioning) {
            return;
        }
        if (AbstractC1136h0.N(2)) {
            h0.toString();
        }
        long jA = C1135h.a.a(animatorSet);
        long j = (long) (backEvent.c * jA);
        if (j == 0) {
            j = 1;
        }
        if (j == jA) {
            j = jA - 1;
        }
        if (AbstractC1136h0.N(2)) {
            animatorSet.toString();
            h0.toString();
        }
        C1137i.a.b(animatorSet, j);
    }

    @Override // androidx.fragment.app.G0
    public final void e(ViewGroup container) throws Resources.NotFoundException {
        C1133g c1133g;
        Intrinsics.checkNotNullParameter(container, "container");
        C1129e c1129e = this.c;
        if (c1129e.a()) {
            return;
        }
        Context context = container.getContext();
        Intrinsics.checkNotNullExpressionValue(context, "context");
        J jB = c1129e.b(context);
        this.d = jB != null ? (AnimatorSet) jB.b : null;
        H0 h0 = c1129e.a;
        Fragment fragment = h0.c;
        boolean z = h0.a == J0.c;
        View view = fragment.mView;
        container.startViewTransition(view);
        AnimatorSet animatorSet = this.d;
        if (animatorSet != null) {
            c1133g = this;
            animatorSet.addListener(new C1131f(container, view, z, h0, c1133g));
        } else {
            c1133g = this;
        }
        AnimatorSet animatorSet2 = c1133g.d;
        if (animatorSet2 != null) {
            animatorSet2.setTarget(view);
        }
    }
}

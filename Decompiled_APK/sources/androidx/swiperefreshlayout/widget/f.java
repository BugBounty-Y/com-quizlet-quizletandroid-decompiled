package androidx.swiperefreshlayout.widget;

import android.view.animation.Animation;

/* loaded from: classes.dex */
public final class f implements Animation.AnimationListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ SwipeRefreshLayout b;

    public /* synthetic */ f(SwipeRefreshLayout swipeRefreshLayout, int i) {
        this.a = i;
        this.b = swipeRefreshLayout;
    }

    private final void a(Animation animation) {
    }

    private final void b(Animation animation) {
    }

    private final void c(Animation animation) {
    }

    private final void d(Animation animation) {
    }

    @Override // android.view.animation.Animation.AnimationListener
    public final void onAnimationEnd(Animation animation) {
        j jVar;
        switch (this.a) {
            case 0:
                SwipeRefreshLayout swipeRefreshLayout = this.b;
                if (!swipeRefreshLayout.c) {
                    swipeRefreshLayout.l();
                    break;
                } else {
                    swipeRefreshLayout.z.setAlpha(255);
                    swipeRefreshLayout.z.start();
                    if (swipeRefreshLayout.E && (jVar = swipeRefreshLayout.b) != null) {
                        jVar.onRefresh();
                    }
                    swipeRefreshLayout.n = swipeRefreshLayout.t.getTop();
                    break;
                }
                break;
            default:
                SwipeRefreshLayout swipeRefreshLayout2 = this.b;
                swipeRefreshLayout2.getClass();
                g gVar = new g(swipeRefreshLayout2, 1);
                swipeRefreshLayout2.B = gVar;
                gVar.setDuration(150L);
                a aVar = swipeRefreshLayout2.t;
                aVar.a = null;
                aVar.clearAnimation();
                swipeRefreshLayout2.t.startAnimation(swipeRefreshLayout2.B);
                break;
        }
    }

    @Override // android.view.animation.Animation.AnimationListener
    public final void onAnimationRepeat(Animation animation) {
        int i = this.a;
    }

    @Override // android.view.animation.Animation.AnimationListener
    public final void onAnimationStart(Animation animation) {
        int i = this.a;
    }
}

package com.google.android.material.search;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.view.View;
import com.google.android.gms.internal.ads.Yh;
import com.google.android.material.internal.ClippableRoundedCornerLayout;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public final class k extends AnimatorListenerAdapter {
    public final /* synthetic */ int a;
    public final /* synthetic */ Yh b;

    public /* synthetic */ k(Yh yh, int i) {
        this.a = i;
        this.b = yh;
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public final void onAnimationEnd(Animator animator) {
        switch (this.a) {
            case 0:
                Yh yh = this.b;
                if (!((SearchView) yh.b).g()) {
                    ((SearchView) yh.b).i();
                }
                ((SearchView) yh.b).setTransitionState(h.d);
                break;
            case 1:
                Yh yh2 = this.b;
                ((ClippableRoundedCornerLayout) yh2.d).setVisibility(8);
                if (!((SearchView) yh2.b).g()) {
                    ((SearchView) yh2.b).f();
                }
                ((SearchView) yh2.b).setTransitionState(h.b);
                break;
            case 2:
                Yh yh3 = this.b;
                if (!((SearchView) yh3.b).g()) {
                    ((SearchView) yh3.b).i();
                }
                ((SearchView) yh3.b).setTransitionState(h.d);
                break;
            default:
                Yh yh4 = this.b;
                ((ClippableRoundedCornerLayout) yh4.d).setVisibility(8);
                if (!((SearchView) yh4.b).g()) {
                    ((SearchView) yh4.b).f();
                }
                ((SearchView) yh4.b).setTransitionState(h.b);
                break;
        }
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public final void onAnimationStart(Animator animator) {
        switch (this.a) {
            case 0:
                Yh yh = this.b;
                ((ClippableRoundedCornerLayout) yh.d).setVisibility(0);
                SearchBar searchBar = (SearchBar) yh.p;
                searchBar.k1.getClass();
                View centerView = searchBar.getCenterView();
                if (centerView != null) {
                    centerView.setAlpha(DefinitionKt.NO_Float_VALUE);
                    break;
                }
                break;
            case 1:
                ((SearchView) this.b.b).setTransitionState(h.a);
                break;
            case 2:
                Yh yh2 = this.b;
                ((ClippableRoundedCornerLayout) yh2.d).setVisibility(0);
                ((SearchView) yh2.b).setTransitionState(h.c);
                break;
            default:
                ((SearchView) this.b.b).setTransitionState(h.a);
                break;
        }
    }
}

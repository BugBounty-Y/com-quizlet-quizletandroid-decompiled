package com.airbnb.lottie;

import java.lang.ref.WeakReference;

/* loaded from: classes.dex */
public final class g implements x {
    public final /* synthetic */ int a;
    public final WeakReference b;

    public g(LottieAnimationView lottieAnimationView, int i) {
        this.a = i;
        switch (i) {
            case 1:
                this.b = new WeakReference(lottieAnimationView);
                break;
            default:
                this.b = new WeakReference(lottieAnimationView);
                break;
        }
    }

    @Override // com.airbnb.lottie.x
    public final void onResult(Object obj) {
        switch (this.a) {
            case 0:
                Throwable th = (Throwable) obj;
                LottieAnimationView lottieAnimationView = (LottieAnimationView) this.b.get();
                if (lottieAnimationView != null) {
                    int i = lottieAnimationView.g;
                    if (i != 0) {
                        lottieAnimationView.setImageResource(i);
                    }
                    x xVar = lottieAnimationView.f;
                    if (xVar == null) {
                        xVar = LottieAnimationView.q;
                    }
                    xVar.onResult(th);
                    break;
                }
                break;
            default:
                h hVar = (h) obj;
                LottieAnimationView lottieAnimationView2 = (LottieAnimationView) this.b.get();
                if (lottieAnimationView2 != null) {
                    lottieAnimationView2.setComposition(hVar);
                    break;
                }
                break;
        }
    }
}

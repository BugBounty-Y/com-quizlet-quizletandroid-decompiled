package com.amazon.device.ads;

import android.animation.ValueAnimator;
import android.view.ViewGroup;

/* loaded from: classes.dex */
public final /* synthetic */ class d implements ValueAnimator.AnimatorUpdateListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ DTBAdMRAIDBannerController b;
    public final /* synthetic */ ViewGroup c;
    public final /* synthetic */ boolean d;

    public /* synthetic */ d(DTBAdMRAIDBannerController dTBAdMRAIDBannerController, ViewGroup viewGroup, boolean z, int i) {
        this.a = i;
        this.b = dTBAdMRAIDBannerController;
        this.c = viewGroup;
        this.d = z;
    }

    @Override // android.animation.ValueAnimator.AnimatorUpdateListener
    public final void onAnimationUpdate(ValueAnimator valueAnimator) {
        switch (this.a) {
            case 0:
                this.b.lambda$moveExpandedToDefaultImpl$3(this.c, this.d, valueAnimator);
                break;
            default:
                this.b.lambda$moveResizedToDefaultImpl$1(this.c, this.d, valueAnimator);
                break;
        }
    }
}

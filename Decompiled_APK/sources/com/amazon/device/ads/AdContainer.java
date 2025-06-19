package com.amazon.device.ads;

import android.content.Context;
import android.view.View;
import android.widget.LinearLayout;

/* loaded from: classes.dex */
class AdContainer extends LinearLayout {
    View adView;
    int orientation;

    public AdContainer(Context context) {
        super(context);
        setOrientation(1);
        this.orientation = AdRegistration.getContext().getResources().getConfiguration().orientation;
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        if (this.orientation == AdRegistration.getContext().getResources().getConfiguration().orientation) {
            View view = this.adView;
            if (view instanceof DTBAdView) {
                ((DTBAdView) view).onAdRemoved();
            }
            this.adView = null;
        }
        this.adView = null;
    }

    public void setAdView(View view) {
        this.adView = view;
    }
}

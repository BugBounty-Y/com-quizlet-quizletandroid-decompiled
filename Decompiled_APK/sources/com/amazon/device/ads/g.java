package com.amazon.device.ads;

import android.view.MotionEvent;
import android.view.View;

/* loaded from: classes.dex */
public final /* synthetic */ class g implements View.OnTouchListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ DTBAdMRAIDController b;

    public /* synthetic */ g(DTBAdMRAIDController dTBAdMRAIDController, int i) {
        this.a = i;
        this.b = dTBAdMRAIDController;
    }

    @Override // android.view.View.OnTouchListener
    public final boolean onTouch(View view, MotionEvent motionEvent) {
        switch (this.a) {
            case 0:
                return this.b.lambda$setCloseIndicatorContent$3(view, motionEvent);
            default:
                return ((DTBAdMRAIDExpandedController) this.b).lambda$addCloseIndicator$0(view, motionEvent);
        }
    }
}

package com.google.android.material.timepicker;

import android.view.ViewTreeObserver;

/* loaded from: classes2.dex */
public final class b implements ViewTreeObserver.OnPreDrawListener {
    public final /* synthetic */ ClockFaceView a;

    public b(ClockFaceView clockFaceView) {
        this.a = clockFaceView;
    }

    @Override // android.view.ViewTreeObserver.OnPreDrawListener
    public final boolean onPreDraw() {
        ClockFaceView clockFaceView = this.a;
        if (!clockFaceView.isShown()) {
            return true;
        }
        clockFaceView.getViewTreeObserver().removeOnPreDrawListener(this);
        int height = ((clockFaceView.getHeight() / 2) - clockFaceView.t.d) - clockFaceView.B;
        if (height != clockFaceView.r) {
            clockFaceView.r = height;
            clockFaceView.p();
            int i = clockFaceView.r;
            ClockHandView clockHandView = clockFaceView.t;
            clockHandView.l = i;
            clockHandView.invalidate();
        }
        return true;
    }
}

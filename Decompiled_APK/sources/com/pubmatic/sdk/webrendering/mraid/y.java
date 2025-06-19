package com.pubmatic.sdk.webrendering.mraid;

import android.view.ViewTreeObserver;
import com.pubmatic.sdk.common.log.POBLog;

/* loaded from: classes2.dex */
public class y implements ViewTreeObserver.OnGlobalLayoutListener {
    final /* synthetic */ C a;

    public y(C c) {
        this.a = c;
    }

    @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
    public void onGlobalLayout() {
        int deviceOrientation = com.pubmatic.sdk.common.utility.o.getDeviceOrientation(this.a.b);
        POBLog.debug("PMResizeView", "currentOrientation :" + this.a.g + ", changedOrientation:" + deviceOrientation, new Object[0]);
        if (deviceOrientation == this.a.g || !this.a.h) {
            return;
        }
        this.a.b();
    }
}

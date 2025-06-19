package com.pubmatic.sdk.webrendering.mraid;

import android.graphics.Bitmap;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.webrendering.mraid.POBMraidController;
import java.util.Calendar;

/* loaded from: classes2.dex */
public class u implements Runnable {
    final /* synthetic */ Bitmap a;
    final /* synthetic */ POBMraidController.a b;

    public u(POBMraidController.a aVar, Bitmap bitmap) {
        this.b = aVar;
        this.a = bitmap;
    }

    @Override // java.lang.Runnable
    public void run() {
        if (C4074c.a(POBMraidController.this.appContext, this.a, Calendar.getInstance().getTimeInMillis() + ".jpeg")) {
            POBLog.info("POBMraidController", "image successfully saved to device!", new Object[0]);
        } else {
            POBLog.error("POBMraidController", "Error saving picture to device through MRAID ad.", new Object[0]);
        }
    }
}

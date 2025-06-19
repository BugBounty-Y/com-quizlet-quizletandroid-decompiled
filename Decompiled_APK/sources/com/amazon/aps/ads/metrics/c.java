package com.amazon.aps.ads.metrics;

import android.view.View;
import com.airbnb.lottie.network.d;
import com.amazon.aps.shared.metrics.model.k;
import com.amazon.aps.shared.metrics.model.l;
import com.amazon.device.ads.DTBAdInterstitialListener;
import com.amazon.device.ads.DTBAdListener;

/* loaded from: classes.dex */
public final class c extends a implements DTBAdInterstitialListener {
    public String b;
    public final DTBAdInterstitialListener c;

    public c(String str, DTBAdInterstitialListener dTBAdInterstitialListener) {
        super(dTBAdInterstitialListener);
        this.b = str;
        this.c = dTBAdInterstitialListener;
    }

    @Override // com.amazon.aps.ads.metrics.a
    public final String a() {
        return this.b;
    }

    @Override // com.amazon.aps.ads.metrics.a
    public final DTBAdListener b() {
        return this.c;
    }

    @Override // com.amazon.aps.ads.metrics.a
    public final void c(String str) {
        this.b = str;
    }

    @Override // com.amazon.device.ads.DTBAdVideoListener
    public final void onVideoCompleted(View view) {
        long jCurrentTimeMillis = System.currentTimeMillis();
        DTBAdInterstitialListener dTBAdInterstitialListener = this.c;
        if (dTBAdInterstitialListener != null) {
            dTBAdInterstitialListener.onVideoCompleted(view);
        }
        String str = this.b;
        d dVar = new d(17);
        dVar.r(this.b);
        ((k) dVar.b).k = new l(jCurrentTimeMillis);
        com.amazon.aps.shared.a.a(str, dVar);
    }
}

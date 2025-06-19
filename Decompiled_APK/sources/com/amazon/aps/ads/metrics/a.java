package com.amazon.aps.ads.metrics;

import android.view.View;
import com.airbnb.lottie.network.d;
import com.amazon.aps.shared.metrics.model.g;
import com.amazon.aps.shared.metrics.model.h;
import com.amazon.aps.shared.metrics.model.j;
import com.amazon.aps.shared.metrics.model.k;
import com.amazon.aps.shared.metrics.model.m;
import com.amazon.device.ads.DTBAdListener;
import com.amazon.device.ads.DTBMetricsConfiguration;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class a implements DTBAdListener {
    public final DTBAdListener a;

    public a(DTBAdListener dTBAdListener) {
        this.a = dTBAdListener;
    }

    public abstract String a();

    public abstract DTBAdListener b();

    public abstract void c(String str);

    @Override // com.amazon.device.ads.DTBAdListener
    public final void onAdClicked(View view) {
        long jCurrentTimeMillis = System.currentTimeMillis();
        DTBAdListener dTBAdListenerB = b();
        if (dTBAdListenerB != null) {
            dTBAdListenerB.onAdClicked(view);
        }
        if (DTBMetricsConfiguration.getInstance().isFeatureEnabled(DTBMetricsConfiguration.FEATURE_APSMETRICS_EXTENDED_METRICS, false)) {
            String strA = a();
            d dVar = new d(17);
            dVar.r(a());
            ((k) dVar.b).j = new g(jCurrentTimeMillis);
            com.amazon.aps.shared.a.a(strA, dVar);
        }
    }

    @Override // com.amazon.device.ads.DTBAdListener
    public final void onAdClosed(View view) {
        DTBAdListener dTBAdListenerB = b();
        if (dTBAdListenerB == null) {
            return;
        }
        dTBAdListenerB.onAdClosed(view);
    }

    @Override // com.amazon.device.ads.DTBAdListener
    public final void onAdError(View view) {
        DTBAdListener dTBAdListenerB = b();
        if (dTBAdListenerB == null) {
            return;
        }
        dTBAdListenerB.onAdError(view);
    }

    @Override // com.amazon.device.ads.DTBAdListener
    public final void onAdFailed(View view) {
        long jCurrentTimeMillis = System.currentTimeMillis();
        DTBAdListener dTBAdListenerB = b();
        if (dTBAdListenerB != null) {
            dTBAdListenerB.onAdFailed(view);
        }
        String strA = a();
        d dVar = new d(17);
        dVar.r(a());
        m result = m.b;
        Intrinsics.checkNotNullParameter(result, "result");
        k kVar = (k) dVar.b;
        h hVar = kVar.h;
        if (hVar == null) {
            hVar = new h(result);
        }
        kVar.h = hVar;
        hVar.d = result;
        hVar.c = jCurrentTimeMillis;
        com.amazon.aps.shared.a.a(strA, dVar);
    }

    @Override // com.amazon.device.ads.DTBAdListener
    public final void onAdLeftApplication(View view) {
        DTBAdListener dTBAdListenerB = b();
        if (dTBAdListenerB == null) {
            return;
        }
        dTBAdListenerB.onAdLeftApplication(view);
    }

    @Override // com.amazon.device.ads.DTBAdListener
    public final void onAdLoaded(View view) {
        long jCurrentTimeMillis = System.currentTimeMillis();
        DTBAdListener dTBAdListenerB = b();
        if (dTBAdListenerB != null) {
            dTBAdListenerB.onAdLoaded(view);
        }
        String strA = a();
        d dVar = new d(17);
        dVar.r(a());
        m result = m.a;
        Intrinsics.checkNotNullParameter(result, "result");
        k kVar = (k) dVar.b;
        h hVar = kVar.h;
        if (hVar == null) {
            hVar = new h(result);
        }
        kVar.h = hVar;
        hVar.d = result;
        hVar.c = jCurrentTimeMillis;
        com.amazon.aps.shared.a.a(strA, dVar);
    }

    @Override // com.amazon.device.ads.DTBAdListener
    public final void onAdOpen(View view) {
        DTBAdListener dTBAdListenerB = b();
        if (dTBAdListenerB == null) {
            return;
        }
        dTBAdListenerB.onAdOpen(view);
    }

    @Override // com.amazon.device.ads.DTBAdListener
    public final void onImpressionFired(View view) {
        long jCurrentTimeMillis = System.currentTimeMillis();
        DTBAdListener dTBAdListenerB = b();
        if (dTBAdListenerB != null) {
            dTBAdListenerB.onImpressionFired(view);
        }
        String strA = a();
        d dVar = new d(17);
        dVar.r(a());
        m result = m.a;
        Intrinsics.checkNotNullParameter(result, "result");
        Intrinsics.checkNotNullParameter(result, "result");
        j jVar = new j(result, 0L, 6);
        jVar.c = jCurrentTimeMillis;
        ((k) dVar.b).i = jVar;
        com.amazon.aps.shared.a.a(strA, dVar);
    }
}

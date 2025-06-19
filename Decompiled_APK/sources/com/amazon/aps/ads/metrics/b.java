package com.amazon.aps.ads.metrics;

import com.amazon.device.ads.DTBAdBannerListener;
import com.amazon.device.ads.DTBAdListener;

/* loaded from: classes.dex */
public final class b extends a implements DTBAdBannerListener {
    public String b;
    public final DTBAdBannerListener c;

    public b(String str, DTBAdBannerListener dTBAdBannerListener) {
        super(dTBAdBannerListener);
        this.b = str;
        this.c = dTBAdBannerListener;
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
}

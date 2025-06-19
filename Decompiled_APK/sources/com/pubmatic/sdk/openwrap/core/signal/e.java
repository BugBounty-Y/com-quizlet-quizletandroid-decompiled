package com.pubmatic.sdk.openwrap.core.signal;

import android.content.Context;
import com.pubmatic.sdk.common.POBAdFormat;
import com.pubmatic.sdk.common.utility.o;
import com.pubmatic.sdk.openwrap.core.v;
import com.pubmatic.sdk.openwrap.core.y;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes2.dex */
public final class e implements i {
    @Override // com.pubmatic.sdk.openwrap.core.signal.i
    @NotNull
    public String generateSignal(@NotNull Context context, @NotNull POBSignalConfig config) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(config, "config");
        POBAdFormat adFormat = config.getAdFormat();
        POBAdFormat pOBAdFormat = POBAdFormat.REWARDEDAD;
        a aVar = new a(adFormat == pOBAdFormat, config.getAdFormat() == POBAdFormat.INTERSTITIAL || config.getAdFormat() == pOBAdFormat);
        int i = d.$EnumSwitchMapping$0[config.getAdFormat().ordinal()];
        if (i == 1) {
            aVar.setBanner(new com.pubmatic.sdk.openwrap.core.c());
        } else if (i == 2) {
            aVar.setBanner(new com.pubmatic.sdk.openwrap.core.c());
            y.b bVar = y.b.IN_BANNER;
            y.a aVar2 = y.a.LINEAR;
            com.pubmatic.sdk.common.f BANNER_SIZE_300x250 = com.pubmatic.sdk.common.f.BANNER_SIZE_300x250;
            Intrinsics.checkNotNullExpressionValue(BANNER_SIZE_300x250, "BANNER_SIZE_300x250");
            aVar.setVideo(new f(bVar, aVar2, BANNER_SIZE_300x250));
        } else if (i == 3) {
            com.pubmatic.sdk.common.f interstitialAdSize = o.getInterstitialAdSize(context.getApplicationContext());
            aVar.setAdPosition(v.b.FULL_SCREEN);
            aVar.setBanner(new com.pubmatic.sdk.openwrap.core.c());
            y.b bVar2 = y.b.INTERSTITIAL;
            y.a aVar3 = y.a.LINEAR;
            Intrinsics.checkNotNullExpressionValue(interstitialAdSize, "interstitialAdSize");
            aVar.setVideo(new f(bVar2, aVar3, interstitialAdSize));
        } else if (i == 4) {
            com.pubmatic.sdk.common.f interstitialAdSize2 = o.getInterstitialAdSize(context.getApplicationContext());
            aVar.setAdPosition(v.b.FULL_SCREEN);
            y.b bVar3 = y.b.INTERSTITIAL;
            y.a aVar4 = y.a.LINEAR;
            Intrinsics.checkNotNullExpressionValue(interstitialAdSize2, "interstitialAdSize");
            aVar.setVideo(new f(bVar3, aVar4, interstitialAdSize2));
        }
        c cVar = new c(context);
        cVar.setRequest(b.getRequest(aVar));
        cVar.setDeviceInfo(com.pubmatic.sdk.common.i.getDeviceInfo(context));
        return cVar.build();
    }
}

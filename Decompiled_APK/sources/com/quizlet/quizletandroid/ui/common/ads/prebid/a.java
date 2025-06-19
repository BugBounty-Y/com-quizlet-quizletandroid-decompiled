package com.quizlet.quizletandroid.ui.common.ads.prebid;

import com.comscore.util.log.LogLevel;
import com.google.android.gms.ads.admanager.AdManagerAdView;
import java.util.EnumSet;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.prebid.mobile.AdSize;
import org.prebid.mobile.BannerAdUnit;
import org.prebid.mobile.LogUtil;
import org.prebid.mobile.api.data.AdFormat;
import org.prebid.mobile.configuration.AdUnitConfiguration;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ g b;

    public /* synthetic */ a(g gVar, int i) {
        this.a = i;
        this.b = gVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                g gVar = this.b;
                com.quizlet.quizletandroid.ui.common.ads.prebid.creators.a aVar = gVar.b;
                com.quizlet.quizletandroid.ui.common.ads.prebid.creators.b input = gVar.d;
                if (input == null) {
                    Intrinsics.m("input");
                    throw null;
                }
                aVar.getClass();
                Intrinsics.checkNotNullParameter(input, "input");
                String strName = input.a.name();
                com.google.android.gms.ads.h hVar = input.b;
                int i = hVar.a;
                BannerAdUnit bannerAdUnit = new BannerAdUnit(strName, EnumSet.of(AdFormat.a));
                AdUnitConfiguration adUnitConfiguration = bannerAdUnit.a;
                AdSize adSize = new AdSize();
                adSize.a = i;
                adSize.b = hVar.b;
                adUnitConfiguration.n.add(adSize);
                AdUnitConfiguration adUnitConfiguration2 = bannerAdUnit.a;
                adUnitConfiguration2.getClass();
                int i2 = (int) (30 * 1000);
                int iMin = Math.min(Math.max(i2, LogLevel.NONE), 120000);
                if (i2 < 30000 || i2 > 120000) {
                    LogUtil.b("Utils", "Refresh interval is out of range. Value which will be used for refresh: " + iMin + ". Make sure that the refresh interval is in the following range: [30000, 120000]");
                }
                adUnitConfiguration2.c = iMin;
                return bannerAdUnit;
            case 1:
                g gVar2 = this.b;
                com.quizlet.data.interactor.course.a aVar2 = gVar2.a;
                com.quizlet.quizletandroid.ui.common.ads.prebid.creators.b input2 = gVar2.d;
                if (input2 == null) {
                    Intrinsics.m("input");
                    throw null;
                }
                aVar2.getClass();
                Intrinsics.checkNotNullParameter(input2, "input");
                AdManagerAdView adManagerAdView = new AdManagerAdView(input2.c.getContext());
                adManagerAdView.setAdListener((n) aVar2.b);
                adManagerAdView.setAdUnitId(input2.c.getContext().getString(input2.a.a));
                adManagerAdView.setAdSizes(input2.b);
                return adManagerAdView;
            default:
                ((AdManagerAdView) this.b.f.getValue()).destroy();
                return Unit.a;
        }
    }
}

package com.braze;

import kotlin.jvm.functions.Function0;

/* renamed from: com.braze.o, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C1509o implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Braze b;

    public /* synthetic */ C1509o(Braze braze, int i) {
        this.a = i;
        this.b = braze;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return Braze.handleInternalBannerRefresh$lambda$191(this.b);
            case 1:
                return Braze.refreshFeatureFlags$lambda$86(this.b);
            case 2:
                return Braze.requestContentCardsRefresh$lambda$81(this.b);
            case 3:
                return Braze.requestFeedRefreshFromCache$lambda$76(this.b);
            case 4:
                return Braze.requestFeedRefresh$lambda$78(this.b);
            case 5:
                return Braze.requestContentCardsRefreshFromCache$lambda$83(this.b);
            case 6:
                return Braze.performPushDeliveryFlush$lambda$205(this.b);
            case 7:
                return Braze.requestImmediateDataFlush$lambda$107(this.b);
            default:
                return Braze.logFeedDisplayed$lambda$74(this.b);
        }
    }
}

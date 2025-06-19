package com.pubmatic.sdk.openwrap.banner;

import android.view.View;
import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.base.j;
import com.pubmatic.sdk.common.h;

/* loaded from: classes2.dex */
public interface b extends com.pubmatic.sdk.openwrap.core.a {
    @Override // com.pubmatic.sdk.openwrap.core.a
    /* synthetic */ j getBidsProvider();

    @Override // com.pubmatic.sdk.openwrap.core.a
    /* synthetic */ void onAdClick();

    @Override // com.pubmatic.sdk.openwrap.core.a
    /* synthetic */ void onAdClosed();

    void onAdExecutionComplete();

    @Override // com.pubmatic.sdk.openwrap.core.a
    /* synthetic */ void onAdImpression();

    @Override // com.pubmatic.sdk.openwrap.core.a
    /* synthetic */ void onAdLeftApplication();

    @Override // com.pubmatic.sdk.openwrap.core.a
    /* synthetic */ void onAdOpened();

    void onAdServerWin(@NonNull View view);

    void onFailed(@NonNull h hVar);

    void onOpenWrapPartnerWin(String str);
}

package com.pubmatic.sdk.common.base;

import androidx.annotation.NonNull;
import java.util.Map;

/* loaded from: classes2.dex */
public abstract class f implements i {
    private String a;
    protected g bidderListener;

    @Override // com.pubmatic.sdk.common.base.i
    public abstract /* synthetic */ void destroy();

    @Override // com.pubmatic.sdk.common.base.i
    public abstract /* synthetic */ com.pubmatic.sdk.common.models.a getAdResponse();

    @Override // com.pubmatic.sdk.common.base.i
    @NonNull
    public abstract /* synthetic */ Map getBidderResults();

    @Override // com.pubmatic.sdk.common.base.i
    public String getIdentifier() {
        return this.a;
    }

    @Override // com.pubmatic.sdk.common.base.i
    public abstract /* synthetic */ void requestBid();

    @Override // com.pubmatic.sdk.common.base.i
    public void setBidderListener(g gVar) {
        this.bidderListener = gVar;
    }

    public void setCountryFilterConfig(e eVar) {
    }

    public void setIdentifier(String str) {
        this.a = str;
    }
}

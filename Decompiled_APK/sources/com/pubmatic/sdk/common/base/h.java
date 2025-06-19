package com.pubmatic.sdk.common.base;

import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public class h {
    private com.pubmatic.sdk.common.models.a a;
    private com.pubmatic.sdk.common.h b;
    private com.pubmatic.sdk.common.network.l c;

    public com.pubmatic.sdk.common.models.a getAdResponse() {
        return this.a;
    }

    public com.pubmatic.sdk.common.h getError() {
        return this.b;
    }

    public com.pubmatic.sdk.common.network.l getNetworkResult() {
        return this.c;
    }

    public void setAdResponse(com.pubmatic.sdk.common.models.a aVar) {
        this.a = aVar;
    }

    public void setError(com.pubmatic.sdk.common.h hVar) {
        this.b = hVar;
    }

    public void setNetworkResult(com.pubmatic.sdk.common.network.l lVar) {
        this.c = lVar;
    }

    @NonNull
    public String toString() {
        return "POBBidderResult{adResponse=" + this.a + ", error=" + this.b + ", networkResult=" + this.c + '}';
    }
}

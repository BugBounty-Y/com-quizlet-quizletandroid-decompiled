package com.pubmatic.sdk.common.base;

import androidx.annotation.NonNull;
import java.util.Map;

/* loaded from: classes2.dex */
public interface i {
    void destroy();

    com.pubmatic.sdk.common.models.a getAdResponse();

    @NonNull
    Map<String, h> getBidderResults();

    String getIdentifier();

    void requestBid();

    void setBidderListener(g gVar);
}

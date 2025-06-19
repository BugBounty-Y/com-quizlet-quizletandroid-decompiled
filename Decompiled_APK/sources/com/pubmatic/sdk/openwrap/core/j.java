package com.pubmatic.sdk.openwrap.core;

import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public class j {
    @NonNull
    public static com.pubmatic.sdk.common.h convertToPOBError(@NonNull g gVar) {
        int i = i.a[gVar.ordinal()];
        return i != 1 ? i != 2 ? new com.pubmatic.sdk.common.h(1006, gVar.getErrorMessage()) : new com.pubmatic.sdk.common.h(com.pubmatic.sdk.common.h.AD_EXPIRED, gVar.getErrorMessage()) : new com.pubmatic.sdk.common.h(com.pubmatic.sdk.common.h.CLIENT_SIDE_AUCTION_LOST, gVar.getErrorMessage());
    }
}

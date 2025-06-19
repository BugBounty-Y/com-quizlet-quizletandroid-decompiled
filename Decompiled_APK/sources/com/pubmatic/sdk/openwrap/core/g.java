package com.pubmatic.sdk.openwrap.core;

import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public enum g {
    CLIENT_SIDE_AUCTION_LOSS("BidEventErrorClientSideAuctionLoss"),
    BID_EXPIRED("BidEventErrorBidExpired"),
    OTHER("BidEventErrorOther");


    @NonNull
    private final String b;

    g(@NonNull String str) {
        this.b = str;
    }

    @NonNull
    public String getErrorMessage() {
        return this.b;
    }
}

package com.pubmatic.sdk.openwrap.core;

/* loaded from: classes2.dex */
public abstract /* synthetic */ class i {
    static final /* synthetic */ int[] a;

    static {
        int[] iArr = new int[g.values().length];
        a = iArr;
        try {
            iArr[g.CLIENT_SIDE_AUCTION_LOSS.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            a[g.BID_EXPIRED.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        try {
            a[g.OTHER.ordinal()] = 3;
        } catch (NoSuchFieldError unused3) {
        }
    }
}

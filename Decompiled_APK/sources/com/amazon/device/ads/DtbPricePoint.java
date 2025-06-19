package com.amazon.device.ads;

/* loaded from: classes.dex */
public class DtbPricePoint {
    private final DTBAdSize adSize;
    private final String pricePoint;

    public DtbPricePoint(String str, String str2, String str3, AdType adType) {
        this.pricePoint = str;
        String[] strArrSplit = str2.split("x");
        if (strArrSplit.length != 2) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.B("AdSize ", str2, " is not valid"));
        }
        this.adSize = new DTBAdSize(DtbCommonUtils.parseInt(strArrSplit[0], 0), DtbCommonUtils.parseInt(strArrSplit[1], 0), adType, str3);
    }

    public DTBAdSize getAdSize() {
        return this.adSize;
    }

    public String getPricePoint() {
        return this.pricePoint;
    }

    public String toString() {
        return "DtbPricePoint [pricePoint=" + this.pricePoint + ", adSize=" + this.adSize + "]";
    }
}

package com.amazon.device.ads;

import org.json.JSONObject;

/* loaded from: classes.dex */
public class DTBAdSize {
    public static final String AAX_INTERSTITIAL_AD_SIZE = "interstitial";
    private final AdType adType;
    private final int height;
    private JSONObject pubSettings;
    private com.amazon.aps.ads.model.c slotInfoExtra;
    private final String slotUUID;
    private final int width;

    public static final class DTBInterstitialAdSize extends DTBAdSize {
        public DTBInterstitialAdSize(String str) {
            super(9999, 9999, AdType.INTERSTITIAL, str, null);
        }
    }

    public static final class DTBVideo extends DTBAdSize {
        public DTBVideo(int i, int i2, String str) {
            super(i, i2, AdType.VIDEO, str, null);
        }

        public DTBVideo(int i, int i2, String str, JSONObject jSONObject) {
            super(i, i2, AdType.VIDEO, str, jSONObject);
        }
    }

    public DTBAdSize(int i, int i2, String str) {
        this(i, i2, AdType.DISPLAY, str, null);
        if (i == 9999 || i2 == 9999) {
            throw new IllegalArgumentException("Invalid size passed, Please use DTBInterstitialAdSize for interstitial ads.");
        }
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        DTBAdSize dTBAdSize = (DTBAdSize) obj;
        return this.height == dTBAdSize.height && this.width == dTBAdSize.width;
    }

    public AdType getDTBAdType() {
        return this.adType;
    }

    public int getHeight() {
        return this.height;
    }

    public JSONObject getPubSettings() {
        return this.pubSettings;
    }

    public com.amazon.aps.ads.model.c getSlotInfoExtra() {
        return null;
    }

    public String getSlotUUID() {
        return this.slotUUID;
    }

    public int getWidth() {
        return this.width;
    }

    public int hashCode() {
        return ((this.height + 31) * 31) + this.width;
    }

    public boolean isInterstitialAd() {
        return this.adType.equals(AdType.INTERSTITIAL);
    }

    public void setPubSettings(JSONObject jSONObject) {
        this.pubSettings = jSONObject;
    }

    public void setSlotInfoExtra(com.amazon.aps.ads.model.c cVar) {
    }

    public String toString() {
        StringBuilder sb = new StringBuilder("DTBAdSize [");
        sb.append(this.width);
        sb.append("x");
        sb.append(this.height);
        sb.append(", adType=");
        sb.append(this.adType);
        sb.append(", slotUUID=");
        return android.support.v4.media.session.a.t(sb, this.slotUUID, "]");
    }

    public DTBAdSize(int i, int i2, AdType adType, String str, JSONObject jSONObject) {
        if (i >= 0 && i2 >= 0 && !DtbCommonUtils.isNullOrEmpty(str)) {
            this.width = i;
            this.height = i2;
            this.adType = adType;
            this.slotUUID = str;
            this.pubSettings = jSONObject;
            return;
        }
        throw new IllegalArgumentException("Invalid parameter(s) passed to DTBAdSize constructor.");
    }

    public DTBAdSize(int i, int i2, AdType adType, String str) {
        this(i, i2, adType, str, null);
        if (i < 0 || i2 < 0 || DtbCommonUtils.isNullOrEmpty(str)) {
            throw new IllegalArgumentException("Invalid parameter(s) passed to DTBAdSize constructor.");
        }
    }
}

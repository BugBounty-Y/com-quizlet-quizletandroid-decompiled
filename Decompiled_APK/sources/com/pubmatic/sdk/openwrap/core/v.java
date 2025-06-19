package com.pubmatic.sdk.openwrap.core;

import androidx.annotation.NonNull;
import java.util.Arrays;

/* loaded from: classes2.dex */
public class v {
    private final p[] a;
    private final int b;

    @NonNull
    private final String c;
    private int d = 5;
    private boolean e;
    private Integer f;
    private boolean g;
    private Boolean h;
    private String i;

    public enum a {
        VPAID1(1),
        VPAID2(2),
        MRAID1(3),
        ORMMA(4),
        MRAID2(5),
        MRAID3(6),
        OMSDK(7);

        private final int b;

        a(int i) {
            this.b = i;
        }

        public int getValue() {
            return this.b;
        }
    }

    public enum b {
        UNKNOWN(0),
        ABOVE_THE_FOLD(1),
        BELOW_THE_FOLD(3),
        HEADER(4),
        FOOTER(5),
        SIDEBAR(6),
        FULL_SCREEN(7);

        private final int b;

        b(int i) {
            this.b = i;
        }

        public int getValue() {
            return this.b;
        }
    }

    private v(@NonNull String str, int i, @NonNull p... pVarArr) {
        this.c = str;
        this.b = i;
        this.a = pVarArr;
    }

    public static v createInstance(@NonNull String str, int i, @NonNull p... pVarArr) {
        if (com.pubmatic.sdk.common.utility.o.isNullOrEmpty(str) || com.pubmatic.sdk.common.utility.o.isNull(pVarArr) || pVarArr.length <= 0) {
            return null;
        }
        return new v(str, i, pVarArr);
    }

    @Deprecated
    public boolean a() {
        return this.e;
    }

    @Deprecated
    public void enableBidSummary(boolean z) {
        this.e = z;
    }

    public void enableDebugState(boolean z) {
        this.g = z;
    }

    public void enableTestMode(boolean z) {
        this.h = Boolean.valueOf(z);
    }

    public String getAdServerUrl() {
        return this.i;
    }

    @NonNull
    public String getAdUnitId() {
        p[] impressions = getImpressions();
        return (impressions == null || impressions.length <= 0) ? "" : impressions[0].getAdUnitId();
    }

    public p[] getImpressions() {
        p[] pVarArr = this.a;
        if (pVarArr == null || pVarArr.length <= 0) {
            return null;
        }
        return (p[]) Arrays.copyOf(pVarArr, pVarArr.length);
    }

    public int getNetworkTimeout() {
        return this.d;
    }

    public int getProfileId() {
        return this.b;
    }

    @NonNull
    public String getPubId() {
        return this.c;
    }

    public Boolean getTestMode() {
        return this.h;
    }

    public Integer getVersionId() {
        return this.f;
    }

    public boolean isDebugStateEnabled() {
        return this.g;
    }

    public void setAdServerUrl(String str) {
        this.i = str;
    }

    public void setNetworkTimeout(int i) {
        if (i > 0) {
            this.d = i;
        }
    }

    public void setVersionId(Integer num) {
        this.f = num;
    }
}

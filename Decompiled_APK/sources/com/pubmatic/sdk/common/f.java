package com.pubmatic.sdk.common;

import androidx.annotation.NonNull;
import com.amazon.device.ads.DtbConstants;

/* loaded from: classes2.dex */
public class f {
    private int a;
    private int b;
    public static final f BANNER_SIZE_320x50 = new f(DtbConstants.DEFAULT_PLAYER_WIDTH, 50);
    public static final f BANNER_SIZE_320x100 = new f(DtbConstants.DEFAULT_PLAYER_WIDTH, 100);
    public static final f BANNER_SIZE_300x250 = new f(300, 250);
    public static final f BANNER_SIZE_250x250 = new f(250, 250);
    public static final f BANNER_SIZE_468x60 = new f(468, 60);
    public static final f BANNER_SIZE_728x90 = new f(728, 90);
    public static final f BANNER_SIZE_120x600 = new f(120, com.pubmatic.sdk.video.a.GENERAL_COMPANION_AD_ERROR);
    public static final f INTERSTITIAL_320x480 = new f(DtbConstants.DEFAULT_PLAYER_WIDTH, DtbConstants.DEFAULT_PLAYER_HEIGHT);
    public static final f INTERSTITIAL_480x320 = new f(DtbConstants.DEFAULT_PLAYER_HEIGHT, DtbConstants.DEFAULT_PLAYER_WIDTH);
    public static final f INTERSTITIAL_768x1024 = new f(768, 1024);
    public static final f INTERSTITIAL_1024x768 = new f(1024, 768);

    public f(int i, int i2) {
        this();
        this.a = i;
        this.b = i2;
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof f)) {
            return false;
        }
        f fVar = (f) obj;
        return this.a == fVar.a && this.b == fVar.b;
    }

    public int getAdHeight() {
        return this.b;
    }

    public int getAdWidth() {
        return this.a;
    }

    public int hashCode() {
        return super.hashCode();
    }

    @NonNull
    public String toString() {
        return this.a + "x" + this.b;
    }

    private f() {
    }
}

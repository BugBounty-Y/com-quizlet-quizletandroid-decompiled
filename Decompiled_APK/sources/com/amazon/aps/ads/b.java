package com.amazon.aps.ads;

import com.amazon.device.ads.AdType;

/* loaded from: classes.dex */
public abstract /* synthetic */ class b {
    public static final /* synthetic */ int[] a;
    public static final /* synthetic */ int[] b;

    static {
        int[] iArr = new int[AdType.values().length];
        b = iArr;
        try {
            iArr[AdType.DISPLAY.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            b[AdType.INTERSTITIAL.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        try {
            b[AdType.VIDEO.ordinal()] = 3;
        } catch (NoSuchFieldError unused3) {
        }
        int[] iArr2 = new int[com.amazon.aps.ads.model.a.values().length];
        a = iArr2;
        try {
            iArr2[3] = 1;
        } catch (NoSuchFieldError unused4) {
        }
        try {
            a[0] = 2;
        } catch (NoSuchFieldError unused5) {
        }
        try {
            a[1] = 3;
        } catch (NoSuchFieldError unused6) {
        }
        try {
            a[2] = 4;
        } catch (NoSuchFieldError unused7) {
        }
        try {
            a[5] = 5;
        } catch (NoSuchFieldError unused8) {
        }
    }
}

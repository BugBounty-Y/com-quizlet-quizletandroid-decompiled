package com.pubmatic.sdk.omsdk;

/* loaded from: classes2.dex */
public abstract /* synthetic */ class c {
    static final /* synthetic */ int[] a;

    static {
        int[] iArr = new int[com.pubmatic.sdk.common.viewability.e.values().length];
        a = iArr;
        try {
            iArr[com.pubmatic.sdk.common.viewability.e.LOADED.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            a[com.pubmatic.sdk.common.viewability.e.IMPRESSION.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
    }
}

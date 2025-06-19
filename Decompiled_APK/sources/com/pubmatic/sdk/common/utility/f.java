package com.pubmatic.sdk.common.utility;

import com.pubmatic.sdk.common.utility.g;

/* loaded from: classes2.dex */
public abstract /* synthetic */ class f {
    static final /* synthetic */ int[] a;

    static {
        int[] iArr = new int[g.a.values().length];
        a = iArr;
        try {
            iArr[g.a.NETWORK.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            a[g.a.GPS.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        try {
            a[g.a.PASSIVE.ordinal()] = 3;
        } catch (NoSuchFieldError unused3) {
        }
    }
}

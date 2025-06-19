package com.pubmatic.sdk.common.network;

import com.pubmatic.sdk.common.network.a;

/* loaded from: classes2.dex */
public abstract /* synthetic */ class f {
    static final /* synthetic */ int[] a;

    static {
        int[] iArr = new int[a.EnumC0011a.values().length];
        a = iArr;
        try {
            iArr[a.EnumC0011a.POST.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            a[a.EnumC0011a.PUT.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        try {
            a[a.EnumC0011a.DELETE.ordinal()] = 3;
        } catch (NoSuchFieldError unused3) {
        }
    }
}

package com.pubmatic.sdk.common.log;

import com.pubmatic.sdk.common.a;

/* loaded from: classes2.dex */
public abstract /* synthetic */ class a {
    static final /* synthetic */ int[] a;

    static {
        int[] iArr = new int[a.EnumC0007a.values().length];
        a = iArr;
        try {
            iArr[a.EnumC0007a.Info.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            a[a.EnumC0007a.Warn.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        try {
            a[a.EnumC0007a.Debug.ordinal()] = 3;
        } catch (NoSuchFieldError unused3) {
        }
        try {
            a[a.EnumC0007a.Verbose.ordinal()] = 4;
        } catch (NoSuchFieldError unused4) {
        }
    }
}

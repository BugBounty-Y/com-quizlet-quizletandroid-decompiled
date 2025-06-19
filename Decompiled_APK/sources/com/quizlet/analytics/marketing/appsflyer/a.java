package com.quizlet.analytics.marketing.appsflyer;

import com.appsflyer.deeplink.DeepLinkResult;

/* loaded from: classes2.dex */
public abstract /* synthetic */ class a {
    public static final /* synthetic */ int[] a;

    static {
        int[] iArr = new int[DeepLinkResult.Status.values().length];
        try {
            iArr[DeepLinkResult.Status.FOUND.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            iArr[DeepLinkResult.Status.NOT_FOUND.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        a = iArr;
    }
}

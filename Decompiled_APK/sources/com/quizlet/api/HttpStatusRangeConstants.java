package com.quizlet.api;

import kotlin.Metadata;

@Metadata
/* loaded from: classes2.dex */
public final class HttpStatusRangeConstants {
    public static final org.apache.commons.lang3.d a = new org.apache.commons.lang3.d(200, 299);
    public static final org.apache.commons.lang3.d b;
    public static final org.apache.commons.lang3.d c;

    static {
        Integer num = 300;
        num.compareTo((Integer) 399);
        b = new org.apache.commons.lang3.d(400, 499);
        c = new org.apache.commons.lang3.d(Integer.valueOf(com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR), 599);
    }
}

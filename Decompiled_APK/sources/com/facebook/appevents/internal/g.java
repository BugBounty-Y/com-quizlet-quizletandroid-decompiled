package com.facebook.appevents.internal;

import com.facebook.o;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class g extends r implements Function0 {
    public static final g a = new g(0);

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        return o.a().getSharedPreferences("com.facebook.sdk.APPLINK_INFO", 0);
    }
}

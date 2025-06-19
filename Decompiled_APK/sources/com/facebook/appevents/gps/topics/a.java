package com.facebook.appevents.gps.topics;

import java.util.concurrent.Executors;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class a extends r implements Function0 {
    public static final a a = new a(0);

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        return Executors.newCachedThreadPool();
    }
}

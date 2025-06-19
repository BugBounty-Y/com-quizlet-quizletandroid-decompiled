package com.quizlet.time;

import java.time.Instant;
import java.util.Calendar;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public static final b a = new b();

    public b() {
        b timeProvider = a;
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
    }

    public static long a() {
        Instant instantNow = Instant.now();
        Intrinsics.checkNotNullExpressionValue(instantNow, "now(...)");
        return instantNow.getEpochSecond();
    }

    public static Calendar b() {
        Calendar calendar = Calendar.getInstance();
        Intrinsics.checkNotNullExpressionValue(calendar, "getInstance(...)");
        return calendar;
    }
}

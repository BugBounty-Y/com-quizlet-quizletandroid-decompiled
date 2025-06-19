package io.ktor.util.date;

import java.util.Calendar;
import java.util.Locale;
import java.util.TimeZone;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class a {
    public static final TimeZone a = TimeZone.getTimeZone("GMT");

    public static final d a(Long l) {
        Calendar calendar = Calendar.getInstance(a, Locale.ROOT);
        Intrinsics.d(calendar);
        Intrinsics.checkNotNullParameter(calendar, "<this>");
        if (l != null) {
            calendar.setTimeInMillis(l.longValue());
        }
        int i = calendar.get(16) + calendar.get(15);
        int i2 = calendar.get(13);
        int i3 = calendar.get(12);
        int i4 = calendar.get(11);
        int i5 = (calendar.get(7) + 5) % 7;
        f.a.getClass();
        f fVar = (f) f.c.get(i5);
        int i6 = calendar.get(5);
        int i7 = calendar.get(6);
        com.quizlet.quizletandroid.ui.onboarding.a aVar = e.a;
        int i8 = calendar.get(2);
        aVar.getClass();
        return new d(i2, i3, i4, fVar, i6, i7, (e) e.c.get(i8), calendar.get(1), calendar.getTimeInMillis() + i);
    }
}

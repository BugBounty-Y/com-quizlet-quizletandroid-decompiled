package com.google.android.material.datepicker;

import java.util.Calendar;

/* loaded from: classes2.dex */
public final class b {
    public static final /* synthetic */ int b = 0;
    public Long a;

    static {
        Month monthA = Month.a(1900, 0);
        Calendar calendarC = v.c(null);
        calendarC.setTimeInMillis(monthA.f);
        v.a(calendarC).getTimeInMillis();
        Month monthA2 = Month.a(2100, 11);
        Calendar calendarC2 = v.c(null);
        calendarC2.setTimeInMillis(monthA2.f);
        v.a(calendarC2).getTimeInMillis();
    }
}

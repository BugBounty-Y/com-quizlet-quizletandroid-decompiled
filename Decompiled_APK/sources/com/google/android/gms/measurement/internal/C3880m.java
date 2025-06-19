package com.google.android.gms.measurement.internal;

import java.util.Calendar;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

/* renamed from: com.google.android.gms.measurement.internal.m, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3880m extends AbstractC3871h0 {
    public long d;
    public String e;

    @Override // com.google.android.gms.measurement.internal.AbstractC3871h0
    public final boolean T() {
        Calendar calendar = Calendar.getInstance();
        this.d = TimeUnit.MINUTES.convert(calendar.get(16) + calendar.get(15), TimeUnit.MILLISECONDS);
        Locale locale = Locale.getDefault();
        String language = locale.getLanguage();
        Locale locale2 = Locale.ENGLISH;
        this.e = android.support.v4.media.session.a.l(language.toLowerCase(locale2), "-", locale.getCountry().toLowerCase(locale2));
        return false;
    }

    public final long W() {
        U();
        return this.d;
    }

    public final String X() {
        U();
        return this.e;
    }
}

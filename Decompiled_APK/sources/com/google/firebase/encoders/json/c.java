package com.google.firebase.encoders.json;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

/* loaded from: classes2.dex */
public final class c implements com.google.firebase.encoders.e {
    public static final SimpleDateFormat a;

    static {
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US);
        a = simpleDateFormat;
        simpleDateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    }

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        ((com.google.firebase.encoders.f) obj2).e(a.format((Date) obj));
    }
}

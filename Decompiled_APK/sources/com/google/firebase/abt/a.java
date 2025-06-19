package com.google.firebase.abt;

import android.text.TextUtils;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/* loaded from: classes2.dex */
public final class a {
    public static final String[] g = {"experimentId", "experimentStartTime", "timeToLiveMillis", "triggerTimeoutMillis", "variantId"};
    public static final SimpleDateFormat h = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", Locale.US);
    public final String a;
    public final String b;
    public final String c;
    public final Date d;
    public final long e;
    public final long f;

    public a(String str, String str2, String str3, Date date, long j, long j2) {
        this.a = str;
        this.b = str2;
        this.c = str3;
        this.d = date;
        this.e = j;
        this.f = j2;
    }

    public final com.google.firebase.analytics.connector.a a() {
        com.google.firebase.analytics.connector.a aVar = new com.google.firebase.analytics.connector.a();
        aVar.a = "frc";
        aVar.m = this.d.getTime();
        aVar.b = this.a;
        aVar.c = this.b;
        String str = this.c;
        if (TextUtils.isEmpty(str)) {
            str = null;
        }
        aVar.d = str;
        aVar.e = this.e;
        aVar.j = this.f;
        return aVar;
    }
}

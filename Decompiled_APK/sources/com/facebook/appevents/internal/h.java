package com.facebook.appevents.internal;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import kotlin.jvm.internal.Intrinsics;
import kotlin.u;

/* loaded from: classes.dex */
public final class h {
    public static final m b = new m();
    public static volatile h c;
    public final u a = kotlin.l.b(g.a);

    public final SharedPreferences a() {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return null;
        }
        try {
            Object value = this.a.getValue();
            Intrinsics.checkNotNullExpressionValue(value, "<get-preferences>(...)");
            return (SharedPreferences) value;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
            return null;
        }
    }

    public final void b(Activity activity) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(activity, "activity");
            Uri data = activity.getIntent().getData();
            if (data == null) {
                return;
            }
            Intent intent = activity.getIntent();
            Intrinsics.checkNotNullExpressionValue(intent, "activity.intent");
            c(data, intent);
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x001c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void c(android.net.Uri r7, android.content.Intent r8) {
        /*
            r6 = this;
            java.lang.String r0 = "intent"
            java.lang.String r1 = "uri"
            boolean r2 = com.facebook.internal.instrument.crashshield.a.b(r6)
            if (r2 == 0) goto Lb
            goto L68
        Lb:
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r1)     // Catch: java.lang.Throwable -> L66
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r8, r0)     // Catch: java.lang.Throwable -> L66
            boolean r2 = com.facebook.internal.instrument.crashshield.a.b(r6)     // Catch: java.lang.Throwable -> L66
            java.lang.String r3 = "al_applink_data"
            r4 = 0
            java.lang.String r5 = "campaign_ids"
            if (r2 == 0) goto L1e
        L1c:
            r7 = r4
            goto L37
        L1e:
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r1)     // Catch: java.lang.Throwable -> L32
            java.lang.String r7 = r7.getQueryParameter(r3)     // Catch: java.lang.Throwable -> L32
            if (r7 != 0) goto L28
            goto L1c
        L28:
            org.json.JSONObject r1 = new org.json.JSONObject     // Catch: java.lang.Exception -> L1c java.lang.Throwable -> L32
            r1.<init>(r7)     // Catch: java.lang.Exception -> L1c java.lang.Throwable -> L32
            java.lang.String r7 = r1.getString(r5)     // Catch: java.lang.Exception -> L1c java.lang.Throwable -> L32
            goto L37
        L32:
            r7 = move-exception
            com.facebook.internal.instrument.crashshield.a.a(r6, r7)     // Catch: java.lang.Throwable -> L66
            goto L1c
        L37:
            if (r7 != 0) goto L54
            boolean r7 = com.facebook.internal.instrument.crashshield.a.b(r6)     // Catch: java.lang.Throwable -> L66
            if (r7 == 0) goto L40
            goto L53
        L40:
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r8, r0)     // Catch: java.lang.Throwable -> L4f
            android.os.Bundle r7 = r8.getBundleExtra(r3)     // Catch: java.lang.Throwable -> L4f
            if (r7 != 0) goto L4a
            goto L53
        L4a:
            java.lang.String r4 = r7.getString(r5)     // Catch: java.lang.Throwable -> L4f
            goto L53
        L4f:
            r7 = move-exception
            com.facebook.internal.instrument.crashshield.a.a(r6, r7)     // Catch: java.lang.Throwable -> L66
        L53:
            r7 = r4
        L54:
            if (r7 == 0) goto L68
            android.content.SharedPreferences r8 = r6.a()     // Catch: java.lang.Throwable -> L66
            android.content.SharedPreferences$Editor r8 = r8.edit()     // Catch: java.lang.Throwable -> L66
            android.content.SharedPreferences$Editor r7 = r8.putString(r5, r7)     // Catch: java.lang.Throwable -> L66
            r7.apply()     // Catch: java.lang.Throwable -> L66
            goto L68
        L66:
            r7 = move-exception
            goto L69
        L68:
            return
        L69:
            com.facebook.internal.instrument.crashshield.a.a(r6, r7)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.internal.h.c(android.net.Uri, android.content.Intent):void");
    }
}

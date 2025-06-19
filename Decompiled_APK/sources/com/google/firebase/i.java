package com.google.firebase;

import android.content.Context;
import android.text.TextUtils;
import com.amazon.device.ads.DTBMetricsConfiguration;
import com.google.android.gms.common.internal.j;
import com.google.android.gms.common.internal.u;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class i {
    public final String a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;
    public final String f;
    public final String g;

    public i(String str, String str2, String str3, String str4, String str5, String str6, String str7) {
        u.j("ApplicationId must be set.", !com.google.android.gms.common.util.e.a(str));
        this.b = str;
        this.a = str2;
        this.c = str3;
        this.d = str4;
        this.e = str5;
        this.f = str6;
        this.g = str7;
    }

    public static i a(Context context) {
        j jVar = new j(context);
        String strA = jVar.a("google_app_id");
        if (TextUtils.isEmpty(strA)) {
            return null;
        }
        return new i(strA, jVar.a("google_api_key"), jVar.a("firebase_database_url"), jVar.a("ga_trackingId"), jVar.a("gcm_defaultSenderId"), jVar.a("google_storage_bucket"), jVar.a("project_id"));
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof i)) {
            return false;
        }
        i iVar = (i) obj;
        return u.l(this.b, iVar.b) && u.l(this.a, iVar.a) && u.l(this.c, iVar.c) && u.l(this.d, iVar.d) && u.l(this.e, iVar.e) && u.l(this.f, iVar.f) && u.l(this.g, iVar.g);
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{this.b, this.a, this.c, this.d, this.e, this.f, this.g});
    }

    public final String toString() {
        androidx.compose.foundation.text.input.internal.u uVar = new androidx.compose.foundation.text.input.internal.u(this);
        uVar.b(this.b, "applicationId");
        uVar.b(this.a, DTBMetricsConfiguration.APSMETRICS_APIKEY);
        uVar.b(this.c, "databaseUrl");
        uVar.b(this.e, "gcmSenderId");
        uVar.b(this.f, "storageBucket");
        uVar.b(this.g, "projectId");
        return uVar.toString();
    }
}

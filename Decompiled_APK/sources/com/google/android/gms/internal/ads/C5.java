package com.google.android.gms.internal.ads;

import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class C5 {
    public final String a;
    public final JSONObject b;
    public final String c;
    public final String d;
    public final boolean e;

    public C5(String str, VersionInfoParcel versionInfoParcel, String str2, JSONObject jSONObject, boolean z) {
        this.d = versionInfoParcel.a;
        this.b = jSONObject;
        this.c = str;
        this.a = str2;
        this.e = z;
    }
}

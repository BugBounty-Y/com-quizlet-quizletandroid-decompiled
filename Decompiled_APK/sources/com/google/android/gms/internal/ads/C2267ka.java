package com.google.android.gms.internal.ads;

import android.content.Context;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;

/* renamed from: com.google.android.gms.internal.ads.ka, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2267ka {
    public static final L9 b = new L9(8);
    public final C2007ea a;

    public C2267ka(Context context, VersionInfoParcel versionInfoParcel, String str, Uq uq) {
        C2007ea c2007ea = new C2007ea();
        c2007ea.c = new Object();
        c2007ea.b = 1;
        c2007ea.a = str;
        c2007ea.d = context.getApplicationContext();
        c2007ea.e = versionInfoParcel;
        c2007ea.f = uq;
        this.a = c2007ea;
    }

    public final com.google.android.gms.ads.internal.c a(String str, InterfaceC2183ia interfaceC2183ia, InterfaceC2139ha interfaceC2139ha) {
        return new com.google.android.gms.ads.internal.c(this.a, str, interfaceC2183ia, interfaceC2139ha);
    }
}

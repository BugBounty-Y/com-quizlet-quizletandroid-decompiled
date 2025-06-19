package com.google.android.gms.measurement.internal;

import android.content.Context;
import android.os.Bundle;
import com.google.android.gms.internal.measurement.zzdh;

/* renamed from: com.google.android.gms.measurement.internal.q0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3889q0 {
    public final Context a;
    public final String b;
    public final String c;
    public final String d;
    public final Boolean e;
    public final long f;
    public final zzdh g;
    public final boolean h;
    public final Long i;
    public final String j;

    public C3889q0(Context context, zzdh zzdhVar, Long l) {
        this.h = true;
        com.google.android.gms.common.internal.u.h(context);
        Context applicationContext = context.getApplicationContext();
        com.google.android.gms.common.internal.u.h(applicationContext);
        this.a = applicationContext;
        this.i = l;
        if (zzdhVar != null) {
            this.g = zzdhVar;
            this.b = zzdhVar.f;
            this.c = zzdhVar.e;
            this.d = zzdhVar.d;
            this.h = zzdhVar.c;
            this.f = zzdhVar.b;
            this.j = zzdhVar.h;
            Bundle bundle = zzdhVar.g;
            if (bundle != null) {
                this.e = Boolean.valueOf(bundle.getBoolean("dataCollectionDefaultEnabled", true));
            }
        }
    }
}

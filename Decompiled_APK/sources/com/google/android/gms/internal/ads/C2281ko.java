package com.google.android.gms.internal.ads;

import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build;

/* renamed from: com.google.android.gms.internal.ads.ko, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2281ko implements Vo {
    public static String d;
    public final /* synthetic */ int a;
    public final C2227jd b;
    public final Context c;

    public /* synthetic */ C2281ko(Context context, C2227jd c2227jd, int i) {
        this.a = i;
        this.c = context;
        this.b = c2227jd;
    }

    public Intent a() {
        IntentFilter intentFilter = new IntentFilter("android.intent.action.BATTERY_CHANGED");
        boolean zBooleanValue = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Ya)).booleanValue();
        Context context = this.c;
        return (!zBooleanValue || Build.VERSION.SDK_INT < 33) ? context.registerReceiver(null, intentFilter) : context.registerReceiver(null, intentFilter, 4);
    }

    @Override // com.google.android.gms.internal.ads.Vo
    public final int zza() {
        switch (this.a) {
            case 0:
                return 61;
            case 1:
                return 13;
            case 2:
                return 14;
            case 3:
                return 18;
            case 4:
                return 57;
            case 5:
                return 27;
            case 6:
                return 37;
            case 7:
                return 59;
            case 8:
                return 38;
            default:
                return 39;
        }
    }

    @Override // com.google.android.gms.internal.ads.Vo
    public final com.google.common.util.concurrent.e zzb() {
        ContentResolver contentResolver;
        switch (this.a) {
            case 0:
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Oc)).booleanValue() && (contentResolver = this.c.getContentResolver()) != null) {
                    return this.b.d(new Q4(contentResolver, 10));
                }
                return AbstractC2025es.E(new C2324lo(false, 0, null));
            case 1:
                return this.b.d(new Q4(this, 13));
            case 2:
                return this.b.d(new Q4(this, 14));
            case 3:
                return this.b.d(new Q4(this, 16));
            case 4:
                return this.b.d(new Q4(this, 17));
            case 5:
                return this.b.d(new Q4(this, 22));
            case 6:
                return this.b.d(new Q4(this, 26));
            case 7:
                return ((Boolean) Q7.b.o()).booleanValue() ? this.b.d(new Q4(this, 27)) : AbstractC2025es.E(new Zo(-1, -1));
            case 8:
                return this.b.d(new Q4(this, 28));
            default:
                return this.b.d(new Q4(this, 29));
        }
    }

    public /* synthetic */ C2281ko(C2227jd c2227jd, Context context, int i) {
        this.a = i;
        this.b = c2227jd;
        this.c = context;
    }
}

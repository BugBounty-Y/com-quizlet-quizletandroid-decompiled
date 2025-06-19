package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.media.AudioManager;
import android.net.Uri;
import android.os.Build;

/* renamed from: com.google.android.gms.internal.ads.ac, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1835ac {
    public int a;
    public int b;
    public final boolean c;
    public final boolean d;
    public final String e;
    public final boolean f;
    public final boolean g;
    public final boolean h;
    public final String i;
    public final String j;
    public final float k;
    public final int l;
    public final int m;
    public final String n;

    /* JADX WARN: Removed duplicated region for block: B:12:0x0063  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public C1835ac(android.content.Context r7) {
        /*
            r6 = this;
            r6.<init>()
            android.content.pm.PackageManager r0 = r7.getPackageManager()
            com.google.android.gms.internal.ads.AbstractC2773w7.a(r7)
            r6.c(r7)
            r6.e(r7)
            r6.d(r7)
            java.util.Locale r1 = java.util.Locale.getDefault()
            java.lang.String r2 = "geo:0,0?q=donuts"
            android.content.pm.ResolveInfo r2 = b(r0, r2)
            r3 = 1
            r4 = 0
            if (r2 == 0) goto L23
            r2 = r3
            goto L24
        L23:
            r2 = r4
        L24:
            r6.c = r2
            java.lang.String r2 = "http://www.google.com"
            android.content.pm.ResolveInfo r2 = b(r0, r2)
            if (r2 == 0) goto L2f
            goto L30
        L2f:
            r3 = r4
        L30:
            r6.d = r3
            java.lang.String r2 = r1.getCountry()
            r6.e = r2
            com.google.android.gms.ads.internal.j r2 = com.google.android.gms.ads.internal.j.C
            com.google.android.gms.ads.internal.util.F r2 = r2.c
            com.google.android.gms.ads.internal.client.q r2 = com.google.android.gms.ads.internal.client.C1614q.f
            com.google.android.gms.ads.internal.util.client.c r2 = r2.a
            boolean r2 = com.google.android.gms.ads.internal.util.client.c.l()
            r6.f = r2
            boolean r2 = com.google.android.gms.common.util.c.l(r7)
            r6.g = r2
            boolean r2 = com.google.android.gms.common.util.c.p(r7)
            r6.h = r2
            java.lang.String r1 = r1.getLanguage()
            r6.i = r1
            java.lang.String r1 = "market://details?id=com.google.android.gms.ads"
            android.content.pm.ResolveInfo r0 = b(r0, r1)
            java.lang.String r1 = "."
            r2 = 0
            if (r0 != 0) goto L65
        L63:
            r0 = r2
            goto L8c
        L65:
            android.content.pm.ActivityInfo r0 = r0.activityInfo
            if (r0 != 0) goto L6a
            goto L63
        L6a:
            com.google.android.gms.common.wrappers.b r3 = com.google.android.gms.common.wrappers.c.a(r7)     // Catch: android.content.pm.PackageManager.NameNotFoundException -> L63
            java.lang.String r5 = r0.packageName     // Catch: android.content.pm.PackageManager.NameNotFoundException -> L63
            android.content.pm.PackageInfo r3 = r3.c(r5, r4)     // Catch: android.content.pm.PackageManager.NameNotFoundException -> L63
            if (r3 == 0) goto L63
            int r3 = r3.versionCode     // Catch: android.content.pm.PackageManager.NameNotFoundException -> L63
            java.lang.String r0 = r0.packageName     // Catch: android.content.pm.PackageManager.NameNotFoundException -> L63
            java.lang.StringBuilder r4 = new java.lang.StringBuilder     // Catch: android.content.pm.PackageManager.NameNotFoundException -> L63
            r4.<init>()     // Catch: android.content.pm.PackageManager.NameNotFoundException -> L63
            r4.append(r3)     // Catch: android.content.pm.PackageManager.NameNotFoundException -> L63
            r4.append(r1)     // Catch: android.content.pm.PackageManager.NameNotFoundException -> L63
            r4.append(r0)     // Catch: android.content.pm.PackageManager.NameNotFoundException -> L63
            java.lang.String r0 = r4.toString()     // Catch: android.content.pm.PackageManager.NameNotFoundException -> L63
        L8c:
            r6.j = r0
            com.google.android.gms.common.wrappers.b r0 = com.google.android.gms.common.wrappers.c.a(r7)     // Catch: java.lang.Exception -> Lb2
            java.lang.String r3 = "com.android.vending"
            r4 = 128(0x80, float:1.8E-43)
            android.content.pm.PackageInfo r0 = r0.c(r3, r4)     // Catch: java.lang.Exception -> Lb2
            if (r0 == 0) goto Lb2
            int r3 = r0.versionCode     // Catch: java.lang.Exception -> Lb2
            java.lang.String r0 = r0.packageName     // Catch: java.lang.Exception -> Lb2
            java.lang.StringBuilder r4 = new java.lang.StringBuilder     // Catch: java.lang.Exception -> Lb2
            r4.<init>()     // Catch: java.lang.Exception -> Lb2
            r4.append(r3)     // Catch: java.lang.Exception -> Lb2
            r4.append(r1)     // Catch: java.lang.Exception -> Lb2
            r4.append(r0)     // Catch: java.lang.Exception -> Lb2
            java.lang.String r2 = r4.toString()     // Catch: java.lang.Exception -> Lb2
        Lb2:
            r6.n = r2
            android.content.res.Resources r7 = r7.getResources()
            if (r7 != 0) goto Lbb
            goto Lcd
        Lbb:
            android.util.DisplayMetrics r7 = r7.getDisplayMetrics()
            if (r7 == 0) goto Lcd
            float r0 = r7.density
            r6.k = r0
            int r0 = r7.widthPixels
            r6.l = r0
            int r7 = r7.heightPixels
            r6.m = r7
        Lcd:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C1835ac.<init>(android.content.Context):void");
    }

    public static ResolveInfo b(PackageManager packageManager, String str) {
        try {
            return packageManager.resolveActivity(new Intent("android.intent.action.VIEW", Uri.parse(str)), 65536);
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.j.C.h.h("DeviceInfo.getResolveInfo", th);
            return null;
        }
    }

    public final C1879bc a() {
        return new C1879bc(this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.n, this.a, this.b, this.k, this.l, this.m);
    }

    public final void c(Context context) {
        AudioManager audioManager = (AudioManager) context.getSystemService("audio");
        if (audioManager != null) {
            try {
                audioManager.getMode();
                audioManager.isMusicActive();
                audioManager.isSpeakerphoneOn();
                audioManager.getStreamVolume(3);
                audioManager.getRingerMode();
                audioManager.getStreamVolume(2);
            } catch (Throwable th) {
                com.google.android.gms.ads.internal.j.C.h.h("DeviceInfo.gatherAudioInfo", th);
            }
        }
    }

    public final void d(Context context) {
        IntentFilter intentFilter = new IntentFilter("android.intent.action.BATTERY_CHANGED");
        Intent intentRegisterReceiver = (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Ya)).booleanValue() || Build.VERSION.SDK_INT < 33) ? context.registerReceiver(null, intentFilter) : context.registerReceiver(null, intentFilter, 4);
        if (intentRegisterReceiver != null) {
            intentRegisterReceiver.getIntExtra("status", -1);
            intentRegisterReceiver.getIntExtra("level", -1);
            intentRegisterReceiver.getIntExtra("scale", -1);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x002d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void e(android.content.Context r6) {
        /*
            r5 = this;
            java.lang.String r0 = "phone"
            java.lang.Object r0 = r6.getSystemService(r0)
            android.telephony.TelephonyManager r0 = (android.telephony.TelephonyManager) r0
            java.lang.String r1 = "connectivity"
            java.lang.Object r1 = r6.getSystemService(r1)
            android.net.ConnectivityManager r1 = (android.net.ConnectivityManager) r1
            r0.getNetworkOperator()
            boolean r2 = com.google.android.gms.common.util.c.j()
            r3 = 0
            if (r2 == 0) goto L2d
            com.google.android.gms.internal.ads.s7 r2 = com.google.android.gms.internal.ads.AbstractC2773w7.F8
            com.google.android.gms.ads.internal.client.r r4 = com.google.android.gms.ads.internal.client.r.d
            com.google.android.gms.internal.ads.u7 r4 = r4.c
            java.lang.Object r2 = r4.a(r2)
            java.lang.Boolean r2 = (java.lang.Boolean) r2
            boolean r2 = r2.booleanValue()
            if (r2 == 0) goto L2d
            goto L31
        L2d:
            int r3 = r0.getNetworkType()
        L31:
            r5.b = r3
            r0.getPhoneType()
            r0 = -2
            r5.a = r0
            r0 = -1
            com.google.android.gms.ads.internal.j r2 = com.google.android.gms.ads.internal.j.C
            com.google.android.gms.ads.internal.util.F r2 = r2.c
            java.lang.String r2 = "android.permission.ACCESS_NETWORK_STATE"
            boolean r6 = com.google.android.gms.ads.internal.util.F.b(r6, r2)
            if (r6 == 0) goto L5f
            android.net.NetworkInfo r6 = r1.getActiveNetworkInfo()
            if (r6 == 0) goto L5a
            int r0 = r6.getType()
            r5.a = r0
            android.net.NetworkInfo$DetailedState r6 = r6.getDetailedState()
            r6.ordinal()
            goto L5c
        L5a:
            r5.a = r0
        L5c:
            r1.isActiveNetworkMetered()
        L5f:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C1835ac.e(android.content.Context):void");
    }

    public C1835ac(Context context, C1879bc c1879bc) {
        AbstractC2773w7.a(context);
        c(context);
        e(context);
        d(context);
        String str = Build.FINGERPRINT;
        String str2 = Build.DEVICE;
        G7.a(context);
        this.c = c1879bc.a;
        this.d = c1879bc.b;
        this.e = c1879bc.c;
        this.f = c1879bc.d;
        this.g = c1879bc.e;
        this.h = c1879bc.f;
        this.i = c1879bc.g;
        this.j = c1879bc.h;
        this.n = c1879bc.i;
        this.k = c1879bc.l;
        this.l = c1879bc.m;
        this.m = c1879bc.n;
    }
}

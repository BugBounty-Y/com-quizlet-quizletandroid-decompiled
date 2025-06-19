package com.google.firebase.messaging;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.util.Log;
import java.util.List;

/* loaded from: classes2.dex */
public final class o {
    public final Context a;
    public String b;
    public String c;
    public int d;
    public int e = 0;

    public o(Context context) {
        this.a = context;
    }

    public static String b(com.google.firebase.h hVar) {
        hVar.a();
        com.google.firebase.i iVar = hVar.c;
        String str = iVar.e;
        if (str != null) {
            return str;
        }
        hVar.a();
        String str2 = iVar.b;
        if (!str2.startsWith("1:")) {
            return str2;
        }
        String[] strArrSplit = str2.split(":");
        if (strArrSplit.length < 2) {
            return null;
        }
        String str3 = strArrSplit[1];
        if (str3.isEmpty()) {
            return null;
        }
        return str3;
    }

    public final synchronized String a() {
        try {
            if (this.b == null) {
                e();
            }
        } catch (Throwable th) {
            throw th;
        }
        return this.b;
    }

    public final PackageInfo c(String str) {
        try {
            return this.a.getPackageManager().getPackageInfo(str, 0);
        } catch (PackageManager.NameNotFoundException e) {
            Log.w("FirebaseMessaging", "Failed to find package " + e);
            return null;
        }
    }

    public final boolean d() {
        int i;
        synchronized (this) {
            i = this.e;
            if (i == 0) {
                PackageManager packageManager = this.a.getPackageManager();
                if (packageManager.checkPermission("com.google.android.c2dm.permission.SEND", "com.google.android.gms") == -1) {
                    Log.e("FirebaseMessaging", "Google Play services missing or without correct permission.");
                    i = 0;
                } else {
                    Intent intent = new Intent("com.google.iid.TOKEN_REQUEST");
                    intent.setPackage("com.google.android.gms");
                    List<ResolveInfo> listQueryBroadcastReceivers = packageManager.queryBroadcastReceivers(intent, 0);
                    if (listQueryBroadcastReceivers == null || listQueryBroadcastReceivers.size() <= 0) {
                        Log.w("FirebaseMessaging", "Failed to resolve IID implementation package, falling back");
                        this.e = 2;
                    } else {
                        this.e = 2;
                    }
                    i = 2;
                }
            }
        }
        return i != 0;
    }

    public final synchronized void e() {
        PackageInfo packageInfoC = c(this.a.getPackageName());
        if (packageInfoC != null) {
            this.b = Integer.toString(packageInfoC.versionCode);
            this.c = packageInfoC.versionName;
        }
    }
}

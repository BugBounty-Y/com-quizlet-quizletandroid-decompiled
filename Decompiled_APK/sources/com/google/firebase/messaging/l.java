package com.google.firebase.messaging;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;

/* loaded from: classes2.dex */
public final class l {
    public final com.google.firebase.events.c a;
    public boolean b;
    public com.google.firebase.components.n c;
    public Boolean d;
    public final /* synthetic */ FirebaseMessaging e;

    public l(FirebaseMessaging firebaseMessaging, com.google.firebase.events.c cVar) {
        this.e = firebaseMessaging;
        this.a = cVar;
    }

    public final synchronized void a() {
        try {
            if (this.b) {
                return;
            }
            Boolean boolB = b();
            this.d = boolB;
            if (boolB == null) {
                com.google.firebase.components.n nVar = new com.google.firebase.components.n(19);
                this.c = nVar;
                com.google.firebase.components.k kVar = (com.google.firebase.components.k) this.a;
                kVar.a(kVar.c, nVar);
            }
            this.b = true;
        } catch (Throwable th) {
            throw th;
        }
    }

    public final Boolean b() {
        ApplicationInfo applicationInfo;
        Bundle bundle;
        com.google.firebase.h hVar = this.e.firebaseApp;
        hVar.a();
        Context context = hVar.a;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.google.firebase.messaging", 0);
        if (sharedPreferences.contains("auto_init")) {
            return Boolean.valueOf(sharedPreferences.getBoolean("auto_init", false));
        }
        try {
            PackageManager packageManager = context.getPackageManager();
            if (packageManager == null || (applicationInfo = packageManager.getApplicationInfo(context.getPackageName(), 128)) == null || (bundle = applicationInfo.metaData) == null || !bundle.containsKey("firebase_messaging_auto_init_enabled")) {
                return null;
            }
            return Boolean.valueOf(applicationInfo.metaData.getBoolean("firebase_messaging_auto_init_enabled"));
        } catch (PackageManager.NameNotFoundException unused) {
            return null;
        }
    }
}

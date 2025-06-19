package com.google.firebase;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import androidx.camera.camera2.internal.c0;

/* loaded from: classes2.dex */
public final /* synthetic */ class d implements com.google.firebase.inject.b {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ d(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // com.google.firebase.inject.b
    public final Object get() {
        ApplicationInfo applicationInfo;
        Bundle bundle;
        switch (this.a) {
            case 0:
                h hVar = (h) this.b;
                String strD = hVar.d();
                Context context = (Context) this.c;
                com.google.firebase.internal.a aVar = new com.google.firebase.internal.a();
                Context contextCreateDeviceProtectedStorageContext = context.createDeviceProtectedStorageContext();
                SharedPreferences sharedPreferences = contextCreateDeviceProtectedStorageContext.getSharedPreferences("com.google.firebase.common.prefs:" + strD, 0);
                boolean z = true;
                if (sharedPreferences.contains("firebase_data_collection_default_enabled")) {
                    z = sharedPreferences.getBoolean("firebase_data_collection_default_enabled", true);
                } else {
                    try {
                        PackageManager packageManager = contextCreateDeviceProtectedStorageContext.getPackageManager();
                        if (packageManager != null && (applicationInfo = packageManager.getApplicationInfo(contextCreateDeviceProtectedStorageContext.getPackageName(), 128)) != null && (bundle = applicationInfo.metaData) != null && bundle.containsKey("firebase_data_collection_default_enabled")) {
                            z = applicationInfo.metaData.getBoolean("firebase_data_collection_default_enabled");
                        }
                    } catch (PackageManager.NameNotFoundException unused) {
                    }
                }
                aVar.a = z;
                return aVar;
            case 1:
                com.google.firebase.components.g gVar = (com.google.firebase.components.g) this.b;
                gVar.getClass();
                com.google.firebase.components.a aVar2 = (com.google.firebase.components.a) this.c;
                return aVar2.f.f(new c0(aVar2, gVar));
            default:
                return new com.google.firebase.heartbeatinfo.h((Context) this.c, (String) this.b);
        }
    }

    public /* synthetic */ d(Context context, String str) {
        this.a = 2;
        this.c = context;
        this.b = str;
    }
}

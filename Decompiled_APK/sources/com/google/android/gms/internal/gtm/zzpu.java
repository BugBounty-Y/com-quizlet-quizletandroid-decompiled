package com.google.android.gms.internal.gtm;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.common.util.c;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

/* loaded from: classes2.dex */
public final class zzpu implements Runnable {
    private final Context zza;
    private final zzpa zzb;
    private final zzpj zzc;
    private final zzpr zzd;

    public zzpu(Context context, zzpj zzpjVar, zzpa zzpaVar) {
        zzpr zzprVar = new zzpr();
        u.h(context);
        this.zza = context;
        u.h(zzpaVar);
        this.zzb = zzpaVar;
        this.zzc = zzpjVar;
        this.zzd = zzprVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        InputStream inputStreamZza;
        if (!zza("android.permission.INTERNET")) {
            zzhi.zza("Missing android.permission.INTERNET. Please add the following declaration to your AndroidManifest.xml: <uses-permission android:name=\"android.permission.INTERNET\" />");
        } else if (zza("android.permission.ACCESS_NETWORK_STATE")) {
            NetworkInfo activeNetworkInfo = ((ConnectivityManager) this.zza.getSystemService("connectivity")).getActiveNetworkInfo();
            if (activeNetworkInfo != null && activeNetworkInfo.isConnected()) {
                zzhi.zzd("Starting to load resource from Network.");
                zzps zzpsVar = new zzps();
                try {
                    String strZza = this.zzd.zza(this.zzc.zza());
                    zzhi.zzd("Loading resource from " + strZza);
                    try {
                        inputStreamZza = zzpsVar.zza(strZza);
                    } catch (zzpw unused) {
                        zzhi.zza("NetworkLoader: Error when loading resource for url: " + strZza);
                        this.zzb.zzb(3, 0);
                        inputStreamZza = null;
                    } catch (FileNotFoundException unused2) {
                        zzhi.zza("NetworkLoader: No data was retrieved from the given url: " + strZza);
                        this.zzb.zzb(2, 0);
                        zzpsVar.zzb();
                        return;
                    } catch (IOException e) {
                        zzhi.zzb("NetworkLoader: Error when loading resource from url: " + strZza + " " + e.getMessage(), e);
                        this.zzb.zzb(1, 0);
                        zzpsVar.zzb();
                        return;
                    }
                    try {
                        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                        c.e(inputStreamZza, byteArrayOutputStream, false);
                        this.zzb.zzc(byteArrayOutputStream.toByteArray());
                        zzpsVar.zzb();
                        return;
                    } catch (IOException e2) {
                        zzhi.zzb("NetworkLoader: Error when parsing downloaded resources from url: " + strZza + " " + e2.getMessage(), e2);
                        this.zzb.zzb(2, 0);
                        zzpsVar.zzb();
                        return;
                    }
                } catch (Throwable th) {
                    zzpsVar.zzb();
                    throw th;
                }
            }
            zzhi.zze("No network connectivity - Offline");
        } else {
            zzhi.zza("Missing android.permission.ACCESS_NETWORK_STATE. Please add the following declaration to your AndroidManifest.xml: <uses-permission android:name=\"android.permission.ACCESS_NETWORK_STATE\" />");
        }
        this.zzb.zzb(0, 0);
    }

    public final boolean zza(String str) {
        Context context = this.zza;
        return context.getPackageManager().checkPermission(str, context.getPackageName()) == 0;
    }
}

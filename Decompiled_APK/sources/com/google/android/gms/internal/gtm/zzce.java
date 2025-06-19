package com.google.android.gms.internal.gtm;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.text.TextUtils;
import android.util.Log;
import com.google.android.gms.analytics.j;

/* loaded from: classes2.dex */
public final class zzce extends zzbr {
    private final zzau zza;

    public zzce(zzbu zzbuVar) {
        super(zzbuVar);
        this.zza = new zzau();
    }

    public final zzau zza() {
        zzV();
        return this.zza;
    }

    @Override // com.google.android.gms.internal.gtm.zzbr
    public final void zzd() {
        j jVarZzq = zzq();
        if (jVarZzq.c == null) {
            synchronized (jVarZzq) {
                try {
                    if (jVarZzq.c == null) {
                        zzau zzauVar = new zzau();
                        PackageManager packageManager = jVarZzq.a.getPackageManager();
                        String packageName = jVarZzq.a.getPackageName();
                        zzauVar.zzi(packageName);
                        zzauVar.zzj(packageManager.getInstallerPackageName(packageName));
                        String str = null;
                        try {
                            PackageInfo packageInfo = packageManager.getPackageInfo(jVarZzq.a.getPackageName(), 0);
                            if (packageInfo != null) {
                                CharSequence applicationLabel = packageManager.getApplicationLabel(packageInfo.applicationInfo);
                                if (!TextUtils.isEmpty(applicationLabel)) {
                                    packageName = applicationLabel.toString();
                                }
                                str = packageInfo.versionName;
                            }
                        } catch (PackageManager.NameNotFoundException unused) {
                            Log.e("GAv4", "Error retrieving package info: appName set to " + packageName);
                        }
                        zzauVar.zzk(packageName);
                        zzauVar.zzl(str);
                        jVarZzq.c = zzauVar;
                    }
                } finally {
                }
            }
        }
        jVarZzq.c.zzc(this.zza);
        zzfg zzfgVarZzB = zzB();
        zzfgVarZzB.zzV();
        String str2 = zzfgVarZzB.zzb;
        if (str2 != null) {
            this.zza.zzk(str2);
        }
        zzfgVarZzB.zzV();
        String str3 = zzfgVarZzB.zza;
        if (str3 != null) {
            this.zza.zzl(str3);
        }
    }
}

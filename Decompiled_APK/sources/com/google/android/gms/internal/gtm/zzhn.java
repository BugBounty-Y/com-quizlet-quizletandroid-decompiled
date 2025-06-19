package com.google.android.gms.internal.gtm;

import android.content.DialogInterface;
import android.content.Intent;

/* loaded from: classes2.dex */
final class zzhn implements DialogInterface.OnClickListener {
    final /* synthetic */ zzho zza;

    public zzhn(zzho zzhoVar) {
        this.zza = zzhoVar;
    }

    @Override // android.content.DialogInterface.OnClickListener
    public final void onClick(DialogInterface dialogInterface, int i) {
        String packageName = this.zza.zza.getPackageName();
        Intent launchIntentForPackage = this.zza.zza.getPackageManager().getLaunchIntentForPackage(packageName);
        if (launchIntentForPackage == null) {
            zzhi.zze("No launch activity found for package name: ".concat(String.valueOf(packageName)));
        } else {
            zzhi.zzc("Invoke the launch activity for package name: ".concat(String.valueOf(packageName)));
            this.zza.zza.startActivity(launchIntentForPackage);
        }
    }
}

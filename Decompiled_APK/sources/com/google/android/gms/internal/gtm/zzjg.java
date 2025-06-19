package com.google.android.gms.internal.gtm;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.RemoteException;
import com.google.android.gms.common.stats.a;

/* loaded from: classes2.dex */
public final class zzjg implements ServiceConnection {
    private final Context zza;
    private final a zzb;
    private volatile boolean zzc = false;
    private volatile boolean zzd = false;
    private zzhg zze;

    public zzjg(Context context, a aVar) {
        this.zza = context;
        this.zzb = aVar;
    }

    private static final void zzf(zzhd zzhdVar, String str) {
        try {
            zzhdVar.zze(false, str);
        } catch (RemoteException e) {
            zzhi.zzb("Error - local callback should not throw RemoteException", e);
        }
    }

    @Override // android.content.ServiceConnection
    public final void onServiceConnected(ComponentName componentName, IBinder iBinder) {
        zzhg zzheVar;
        synchronized (this) {
            if (iBinder == null) {
                zzheVar = null;
            } else {
                try {
                    IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.tagmanager.internal.ITagManagerService");
                    zzheVar = iInterfaceQueryLocalInterface instanceof zzhg ? (zzhg) iInterfaceQueryLocalInterface : new zzhe(iBinder);
                } catch (Throwable th) {
                    throw th;
                }
            }
            this.zze = zzheVar;
            this.zzc = true;
            this.zzd = false;
            notifyAll();
        }
    }

    @Override // android.content.ServiceConnection
    public final void onServiceDisconnected(ComponentName componentName) {
        synchronized (this) {
            this.zze = null;
            this.zzc = false;
            this.zzd = false;
        }
    }

    public final void zza() {
        if (zzd()) {
            try {
                this.zze.zze();
            } catch (RemoteException e) {
                zzhi.zzf("Error calling service to dispatch pending events", e);
            }
        }
    }

    public final void zzb(String str, Bundle bundle, String str2, long j, boolean z) {
        if (zzd()) {
            try {
                this.zze.zzf(str, bundle, str2, j, z);
            } catch (RemoteException e) {
                zzhi.zzf("Error calling service to emit event", e);
            }
        }
    }

    public final void zzc(String str, String str2, String str3, zzhd zzhdVar) {
        if (!zzd()) {
            zzf(zzhdVar, str);
            return;
        }
        try {
            this.zze.zzh(str, str2, null, zzhdVar);
        } catch (RemoteException e) {
            zzhi.zzf("Error calling service to load container", e);
            zzf(zzhdVar, str);
        }
    }

    public final boolean zzd() {
        if (this.zzc) {
            return true;
        }
        synchronized (this) {
            try {
                if (this.zzc) {
                    return true;
                }
                if (!this.zzd) {
                    Intent intent = new Intent("ignored");
                    intent.setAction(null);
                    intent.setClassName(this.zza.getPackageName(), "com.google.android.gms.tagmanager.TagManagerService");
                    if (!this.zzb.a(this.zza, intent, this, 1)) {
                        return false;
                    }
                    this.zzd = true;
                }
                while (this.zzd) {
                    try {
                        wait();
                        this.zzd = false;
                    } catch (InterruptedException e) {
                        zzhi.zzf("Error connecting to TagManagerService", e);
                        this.zzd = false;
                    }
                }
                return this.zzc;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final boolean zze() {
        if (!zzd()) {
            return false;
        }
        try {
            this.zze.zzi();
            return true;
        } catch (RemoteException e) {
            zzhi.zzf("Error in resetting service", e);
            return false;
        }
    }
}

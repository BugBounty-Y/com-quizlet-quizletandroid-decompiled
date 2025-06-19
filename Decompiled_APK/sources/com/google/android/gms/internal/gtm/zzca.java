package com.google.android.gms.internal.gtm;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.os.IInterface;
import android.os.RemoteException;
import com.google.android.gms.analytics.j;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.common.stats.a;

/* loaded from: classes2.dex */
public final class zzca implements ServiceConnection {
    final /* synthetic */ zzcb zza;
    private volatile boolean zzb;
    private volatile zzel zzc;

    public zzca(zzcb zzcbVar) {
        this.zza = zzcbVar;
    }

    @Override // android.content.ServiceConnection
    public final void onServiceConnected(ComponentName componentName, IBinder iBinder) {
        u.d("AnalyticsServiceConnection.onServiceConnected");
        synchronized (this) {
            try {
                if (iBinder == null) {
                    this.zza.zzI("Service connected with null binder");
                    return;
                }
                zzel zzelVar = null;
                try {
                    String interfaceDescriptor = iBinder.getInterfaceDescriptor();
                    if ("com.google.android.gms.analytics.internal.IAnalyticsService".equals(interfaceDescriptor)) {
                        IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.analytics.internal.IAnalyticsService");
                        zzelVar = iInterfaceQueryLocalInterface instanceof zzel ? (zzel) iInterfaceQueryLocalInterface : new zzel(iBinder);
                        this.zza.zzN("Bound to IAnalyticsService interface");
                    } else {
                        this.zza.zzJ("Got binder with a wrong descriptor", interfaceDescriptor);
                    }
                } catch (RemoteException unused) {
                    this.zza.zzI("Service connect failed to get IAnalyticsService");
                }
                if (zzelVar == null) {
                    try {
                        a.b().c(this.zza.zzo(), this.zza.zza);
                    } catch (IllegalArgumentException unused2) {
                    }
                } else if (this.zzb) {
                    this.zzc = zzelVar;
                } else {
                    this.zza.zzQ("onServiceConnected received after the timeout limit");
                    j jVarZzq = this.zza.zzq();
                    zzby zzbyVar = new zzby(this, zzelVar);
                    jVarZzq.getClass();
                    jVarZzq.b.submit(zzbyVar);
                }
            } finally {
                notifyAll();
            }
        }
    }

    @Override // android.content.ServiceConnection
    public final void onServiceDisconnected(ComponentName componentName) {
        u.d("AnalyticsServiceConnection.onServiceDisconnected");
        j jVarZzq = this.zza.zzq();
        zzbz zzbzVar = new zzbz(this, componentName);
        jVarZzq.getClass();
        jVarZzq.b.submit(zzbzVar);
    }

    public final zzel zza() {
        j.a();
        Intent intent = new Intent("com.google.android.gms.analytics.service.START");
        intent.setComponent(new ComponentName("com.google.android.gms", "com.google.android.gms.analytics.service.AnalyticsService"));
        Context contextZzo = this.zza.zzo();
        intent.putExtra("app_package_name", contextZzo.getPackageName());
        a aVarB = a.b();
        synchronized (this) {
            this.zzc = null;
            this.zzb = true;
            boolean zA = aVarB.a(contextZzo, intent, this.zza.zza, 129);
            this.zza.zzO("Bind to service requested", Boolean.valueOf(zA));
            if (!zA) {
                this.zzb = false;
                return null;
            }
            try {
                this.zza.zzw();
                wait(((Long) zzeh.zzB.zzb()).longValue());
            } catch (InterruptedException unused) {
                this.zza.zzQ("Wait for service connect was interrupted");
            }
            this.zzb = false;
            zzel zzelVar = this.zzc;
            this.zzc = null;
            if (zzelVar == null) {
                this.zza.zzI("Successfully bound to service but never got onServiceConnected callback");
            }
            return zzelVar;
        }
    }
}

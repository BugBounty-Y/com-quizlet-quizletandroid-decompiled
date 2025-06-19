package com.google.android.gms.internal.gtm;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import androidx.core.content.c;
import com.google.android.gms.analytics.j;
import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
final class zzep extends BroadcastReceiver {
    static final String zza = "com.google.android.gms.internal.gtm.zzep";
    private final zzbu zzb;
    private boolean zzc;
    private boolean zzd;

    public zzep(zzbu zzbuVar) {
        u.h(zzbuVar);
        this.zzb = zzbuVar;
    }

    @Override // android.content.BroadcastReceiver
    public final void onReceive(Context context, Intent intent) {
        this.zzb.zzm();
        this.zzb.zzf();
        String action = intent.getAction();
        this.zzb.zzm().zzO("NetworkBroadcastReceiver received action", action);
        if (!"android.net.conn.CONNECTIVITY_CHANGE".equals(action)) {
            if (!"com.google.analytics.RADIO_POWERED".equals(action)) {
                this.zzb.zzm().zzR("NetworkBroadcastReceiver received unknown action", action);
                return;
            } else {
                if (intent.hasExtra(zza)) {
                    return;
                }
                zzbp zzbpVarZzf = this.zzb.zzf();
                zzbpVarZzf.zzN("Radio powered up");
                zzbpVarZzf.zzc();
                return;
            }
        }
        boolean zZze = zze();
        if (this.zzd != zZze) {
            this.zzd = zZze;
            zzbp zzbpVarZzf2 = this.zzb.zzf();
            zzbpVarZzf2.zzO("Network connectivity status changed", Boolean.valueOf(zZze));
            j jVarZzq = zzbpVarZzf2.zzq();
            zzbi zzbiVar = new zzbi(zzbpVarZzf2, zZze);
            jVarZzq.getClass();
            jVarZzq.b.submit(zzbiVar);
        }
    }

    public final void zza() {
        this.zzb.zzm();
        this.zzb.zzf();
        if (this.zzc) {
            return;
        }
        Context contextZza = this.zzb.zza();
        c.f(contextZza, this, new IntentFilter("android.net.conn.CONNECTIVITY_CHANGE"), 4);
        IntentFilter intentFilter = new IntentFilter("com.google.analytics.RADIO_POWERED");
        intentFilter.addCategory(contextZza.getPackageName());
        c.f(contextZza, this, intentFilter, 4);
        this.zzd = zze();
        this.zzb.zzm().zzO("Registering connectivity change receiver. Network connected", Boolean.valueOf(this.zzd));
        this.zzc = true;
    }

    public final void zzb() {
        Context contextZza = this.zzb.zza();
        Intent intent = new Intent("com.google.analytics.RADIO_POWERED");
        intent.addCategory(contextZza.getPackageName());
        intent.putExtra(zza, true);
        contextZza.sendOrderedBroadcast(intent, null);
    }

    public final void zzc() {
        if (this.zzc) {
            this.zzb.zzm().zzN("Unregistering connectivity change receiver");
            this.zzc = false;
            this.zzd = false;
            try {
                this.zzb.zza().unregisterReceiver(this);
            } catch (IllegalArgumentException e) {
                this.zzb.zzm().zzJ("Failed to unregister the network broadcast receiver", e);
            }
        }
    }

    public final boolean zzd() {
        if (!this.zzc) {
            this.zzb.zzm().zzQ("Connectivity unknown. Receiver not registered");
        }
        return this.zzd;
    }

    public final boolean zze() {
        try {
            NetworkInfo activeNetworkInfo = ((ConnectivityManager) this.zzb.zza().getSystemService("connectivity")).getActiveNetworkInfo();
            if (activeNetworkInfo != null) {
                if (activeNetworkInfo.isConnected()) {
                    return true;
                }
            }
        } catch (SecurityException unused) {
        }
        return false;
    }
}

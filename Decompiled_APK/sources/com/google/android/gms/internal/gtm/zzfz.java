package com.google.android.gms.internal.gtm;

import com.google.android.gms.ads.identifier.a;
import com.google.android.gms.ads.identifier.b;
import com.google.android.gms.common.GooglePlayServicesNotAvailableException;
import com.google.android.gms.common.GooglePlayServicesRepairableException;
import java.io.IOException;

/* loaded from: classes2.dex */
final class zzfz implements zzgb {
    final /* synthetic */ zzgc zza;

    public zzfz(zzgc zzgcVar) {
        this.zza = zzgcVar;
    }

    @Override // com.google.android.gms.internal.gtm.zzgb
    public final a zza() {
        try {
            return b.a(this.zza.zzj);
        } catch (GooglePlayServicesNotAvailableException e) {
            this.zza.zze = false;
            zzhi.zzf("GooglePlayServicesNotAvailableException getting Advertising Id Info", e);
            return null;
        } catch (GooglePlayServicesRepairableException e2) {
            zzhi.zzf("GooglePlayServicesRepairableException getting Advertising Id Info", e2);
            return null;
        } catch (IOException e3) {
            zzhi.zzf("IOException getting Ad Id Info", e3);
            return null;
        } catch (IllegalStateException e4) {
            zzhi.zzf("IllegalStateException getting Advertising Id Info", e4);
            return null;
        } catch (Exception e5) {
            zzhi.zzf("Unknown exception. Could not get the Advertising Id Info.", e5);
            return null;
        }
    }
}

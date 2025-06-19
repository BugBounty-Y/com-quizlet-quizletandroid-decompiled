package com.google.android.gms.common.internal;

import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.util.Log;

/* loaded from: classes2.dex */
public final class x extends com.google.android.gms.internal.p000authapi.g {
    public AbstractC1655e b;
    public final int c;

    public x(AbstractC1655e abstractC1655e, int i) {
        super("com.google.android.gms.common.internal.IGmsCallbacks", 2);
        this.b = abstractC1655e;
        this.c = i;
    }

    @Override // com.google.android.gms.internal.p000authapi.g
    public final boolean p3(int i, Parcel parcel, Parcel parcel2) {
        if (i == 1) {
            int i2 = parcel.readInt();
            IBinder strongBinder = parcel.readStrongBinder();
            Bundle bundle = (Bundle) com.google.android.gms.internal.common.h.a(parcel, Bundle.CREATOR);
            com.google.android.gms.internal.common.h.c(parcel);
            u.i(this.b, "onPostInitComplete can be called only once per call to getRemoteService");
            AbstractC1655e abstractC1655e = this.b;
            abstractC1655e.getClass();
            z zVar = new z(abstractC1655e, i2, strongBinder, bundle);
            w wVar = abstractC1655e.f;
            wVar.sendMessage(wVar.obtainMessage(1, this.c, -1, zVar));
            this.b = null;
        } else if (i == 2) {
            parcel.readInt();
            com.google.android.gms.internal.common.h.c(parcel);
            Log.wtf("GmsClient", "received deprecated onAccountValidationComplete callback, ignoring", new Exception());
        } else {
            if (i != 3) {
                return false;
            }
            int i3 = parcel.readInt();
            IBinder strongBinder2 = parcel.readStrongBinder();
            zzj zzjVar = (zzj) com.google.android.gms.internal.common.h.a(parcel, zzj.CREATOR);
            com.google.android.gms.internal.common.h.c(parcel);
            AbstractC1655e abstractC1655e2 = this.b;
            u.i(abstractC1655e2, "onPostInitCompleteWithConnectionInfo can be called only once per call togetRemoteService");
            u.h(zzjVar);
            abstractC1655e2.w = zzjVar;
            if (abstractC1655e2.s()) {
                ConnectionTelemetryConfiguration connectionTelemetryConfiguration = zzjVar.d;
                i iVarA = i.a();
                RootTelemetryConfiguration rootTelemetryConfiguration = connectionTelemetryConfiguration == null ? null : connectionTelemetryConfiguration.a;
                synchronized (iVarA) {
                    if (rootTelemetryConfiguration == null) {
                        rootTelemetryConfiguration = i.c;
                    } else {
                        RootTelemetryConfiguration rootTelemetryConfiguration2 = (RootTelemetryConfiguration) iVarA.a;
                        if (rootTelemetryConfiguration2 == null || rootTelemetryConfiguration2.a < rootTelemetryConfiguration.a) {
                        }
                    }
                    iVarA.a = rootTelemetryConfiguration;
                }
            }
            Bundle bundle2 = zzjVar.a;
            u.i(this.b, "onPostInitComplete can be called only once per call to getRemoteService");
            AbstractC1655e abstractC1655e3 = this.b;
            abstractC1655e3.getClass();
            z zVar2 = new z(abstractC1655e3, i3, strongBinder2, bundle2);
            w wVar2 = abstractC1655e3.f;
            wVar2.sendMessage(wVar2.obtainMessage(1, this.c, -1, zVar2));
            this.b = null;
        }
        parcel2.writeNoException();
        return true;
    }
}

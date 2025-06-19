package com.google.android.gms.measurement.internal;

import android.os.Bundle;
import android.os.RemoteException;

/* loaded from: classes2.dex */
public final class u1 implements InterfaceC3887p0 {
    public final com.google.android.gms.internal.measurement.P a;
    public final /* synthetic */ AppMeasurementDynamiteService b;

    public u1(AppMeasurementDynamiteService appMeasurementDynamiteService, com.google.android.gms.internal.measurement.P p) {
        this.b = appMeasurementDynamiteService;
        this.a = p;
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3887p0
    public final void onEvent(String str, String str2, Bundle bundle, long j) {
        try {
            this.a.H3(str, str2, bundle, j);
        } catch (RemoteException e) {
            Y y = this.b.a;
            if (y != null) {
                I i = y.i;
                Y.k(i);
                i.j.g("Event listener threw exception", e);
            }
        }
    }
}

package com.google.android.gms.measurement.internal;

import android.os.IBinder;
import android.os.IInterface;
import com.google.android.gms.common.internal.AbstractC1655e;

/* loaded from: classes2.dex */
public final class E extends AbstractC1655e {
    @Override // com.google.android.gms.common.internal.AbstractC1655e, com.google.android.gms.common.api.c
    public final int a() {
        return 12451000;
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final /* synthetic */ IInterface d(IBinder iBinder) {
        if (iBinder == null) {
            return null;
        }
        IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.measurement.internal.IMeasurementService");
        return iInterfaceQueryLocalInterface instanceof InterfaceC3897v ? (InterfaceC3897v) iInterfaceQueryLocalInterface : new C3895u(iBinder);
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final String n() {
        return "com.google.android.gms.measurement.internal.IMeasurementService";
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final String o() {
        return "com.google.android.gms.measurement.START";
    }
}

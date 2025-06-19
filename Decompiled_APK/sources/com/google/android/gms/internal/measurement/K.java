package com.google.android.gms.internal.measurement;

import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import com.google.android.gms.internal.ads.AbstractC2771w5;

/* loaded from: classes2.dex */
public final class K extends AbstractC2771w5 implements L {
    public K(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.measurement.api.internal.IBundleReceiver", 4);
    }

    @Override // com.google.android.gms.internal.measurement.L
    public final void t1(Bundle bundle) {
        Parcel parcelF3 = f3();
        AbstractC3081y.c(parcelF3, bundle);
        v3(1, parcelF3);
    }
}

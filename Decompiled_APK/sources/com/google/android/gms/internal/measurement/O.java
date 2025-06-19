package com.google.android.gms.internal.measurement;

import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import com.google.android.gms.internal.ads.AbstractC2771w5;

/* loaded from: classes2.dex */
public final class O extends AbstractC2771w5 implements P {
    public O(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.measurement.api.internal.IEventHandlerProxy", 4);
    }

    @Override // com.google.android.gms.internal.measurement.P
    public final void H3(String str, String str2, Bundle bundle, long j) {
        Parcel parcelF3 = f3();
        parcelF3.writeString(str);
        parcelF3.writeString(str2);
        AbstractC3081y.c(parcelF3, bundle);
        parcelF3.writeLong(j);
        v3(1, parcelF3);
    }

    @Override // com.google.android.gms.internal.measurement.P
    public final int zze() {
        Parcel parcelP3 = p3(2, f3());
        int i = parcelP3.readInt();
        parcelP3.recycle();
        return i;
    }
}

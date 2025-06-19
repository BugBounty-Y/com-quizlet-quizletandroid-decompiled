package com.google.android.gms.internal.measurement;

import android.os.Parcel;
import kotlinx.coroutines.DispatchException;

/* loaded from: classes2.dex */
public final class Y extends AbstractBinderC3076x implements N {
    public final /* synthetic */ com.google.android.gms.measurement.internal.A0 a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Y(com.google.android.gms.measurement.internal.A0 a0) {
        super("com.google.android.gms.measurement.api.internal.IDynamiteUploadBatchesCallback");
        this.a = a0;
    }

    @Override // com.google.android.gms.internal.measurement.AbstractBinderC3076x
    public final boolean V(int i, Parcel parcel, Parcel parcel2) throws DispatchException {
        if (i != 2) {
            return false;
        }
        zze();
        return true;
    }

    @Override // com.google.android.gms.internal.measurement.N
    public final void zze() throws DispatchException {
        this.a.run();
    }
}

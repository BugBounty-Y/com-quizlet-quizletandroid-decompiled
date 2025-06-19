package com.google.android.gms.ads.internal.client;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import com.google.android.gms.internal.ads.AbstractC2771w5;
import com.google.android.gms.internal.ads.AbstractC2857y5;

/* loaded from: classes2.dex */
public final class t0 extends AbstractC2771w5 implements v0 {
    public t0(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.ads.internal.client.IVideoController", 0);
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final void e2(w0 w0Var) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, w0Var);
        d4(8, parcelF3);
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final float f() {
        throw null;
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final float h() {
        throw null;
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final float zze() {
        throw null;
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final w0 zzi() {
        w0 w0Var;
        Parcel parcelY3 = Y3(11, f3());
        IBinder strongBinder = parcelY3.readStrongBinder();
        if (strongBinder == null) {
            w0Var = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.client.IVideoLifecycleCallbacks");
            w0Var = iInterfaceQueryLocalInterface instanceof w0 ? (w0) iInterfaceQueryLocalInterface : new w0(strongBinder);
        }
        parcelY3.recycle();
        return w0Var;
    }
}

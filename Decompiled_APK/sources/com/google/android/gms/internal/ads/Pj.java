package com.google.android.gms.internal.ads;

import android.os.Parcel;

/* loaded from: classes2.dex */
public final class Pj extends AbstractBinderC2814x5 implements O9 {
    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        if (i != 1) {
            if (i != 2) {
                return false;
            }
            parcel.readInt();
            AbstractC2857y5.b(parcel);
        }
        parcel2.writeNoException();
        return true;
    }

    @Override // com.google.android.gms.internal.ads.O9
    public final void f() {
    }

    @Override // com.google.android.gms.internal.ads.O9
    public final void u(int i) {
    }
}

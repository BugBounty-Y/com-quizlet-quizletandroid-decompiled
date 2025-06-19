package com.google.android.gms.internal.ads;

import android.os.Parcel;

/* loaded from: classes2.dex */
public final class N9 extends AbstractC2771w5 implements O9 {
    @Override // com.google.android.gms.internal.ads.O9
    public final void f() {
        d4(1, f3());
    }

    @Override // com.google.android.gms.internal.ads.O9
    public final void u(int i) {
        Parcel parcelF3 = f3();
        parcelF3.writeInt(i);
        d4(2, parcelF3);
    }
}

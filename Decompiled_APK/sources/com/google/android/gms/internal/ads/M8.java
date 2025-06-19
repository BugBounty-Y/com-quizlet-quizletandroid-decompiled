package com.google.android.gms.internal.ads;

import android.os.Parcel;

/* loaded from: classes2.dex */
public final class M8 extends AbstractC2771w5 implements N8 {
    @Override // com.google.android.gms.internal.ads.N8
    public final void e3(J8 j8, String str) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, j8);
        parcelF3.writeString(str);
        d4(1, parcelF3);
    }
}

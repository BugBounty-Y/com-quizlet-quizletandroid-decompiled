package com.google.android.gms.internal.ads;

import android.os.Parcel;
import java.util.List;

/* loaded from: classes2.dex */
public final class I9 extends AbstractC2771w5 implements K9 {
    @Override // com.google.android.gms.internal.ads.K9
    public final void S2(List list) {
        Parcel parcelF3 = f3();
        parcelF3.writeTypedList(list);
        d4(1, parcelF3);
    }
}

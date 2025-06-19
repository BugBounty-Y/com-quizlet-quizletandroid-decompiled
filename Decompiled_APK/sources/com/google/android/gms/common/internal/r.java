package com.google.android.gms.common.internal;

import android.os.Parcel;
import com.google.android.gms.internal.ads.AbstractC2771w5;

/* loaded from: classes2.dex */
public final class r extends AbstractC2771w5 implements t {
    public final boolean h4() {
        Parcel parcelL2 = L2(7, f3());
        int i = com.google.android.gms.internal.common.h.a;
        boolean z = parcelL2.readInt() != 0;
        parcelL2.recycle();
        return z;
    }
}

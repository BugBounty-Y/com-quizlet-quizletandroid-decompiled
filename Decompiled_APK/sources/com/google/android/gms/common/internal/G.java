package com.google.android.gms.common.internal;

import android.os.Parcel;
import com.google.android.gms.internal.ads.AbstractC2771w5;

/* loaded from: classes2.dex */
public final class G extends AbstractC2771w5 implements H {
    @Override // com.google.android.gms.common.internal.H
    public final com.google.android.gms.dynamic.a j() {
        return assistantMode.refactored.a.h(L2(1, f3()));
    }

    @Override // com.google.android.gms.common.internal.H
    public final int zze() {
        Parcel parcelL2 = L2(2, f3());
        int i = parcelL2.readInt();
        parcelL2.recycle();
        return i;
    }
}

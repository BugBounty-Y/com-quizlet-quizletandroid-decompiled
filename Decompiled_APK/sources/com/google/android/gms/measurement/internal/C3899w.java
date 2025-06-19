package com.google.android.gms.measurement.internal;

import android.os.Parcel;
import com.google.android.gms.internal.ads.AbstractC2771w5;
import java.util.List;

/* renamed from: com.google.android.gms.measurement.internal.w, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3899w extends AbstractC2771w5 implements InterfaceC3901x {
    @Override // com.google.android.gms.measurement.internal.InterfaceC3901x
    public final void w3(List list) {
        Parcel parcelF3 = f3();
        parcelF3.writeTypedList(list);
        I3(parcelF3);
    }
}

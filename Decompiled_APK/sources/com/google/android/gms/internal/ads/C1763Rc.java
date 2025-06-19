package com.google.android.gms.internal.ads;

import android.os.Bundle;
import android.os.Parcel;

/* renamed from: com.google.android.gms.internal.ads.Rc, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1763Rc extends AbstractC2771w5 implements InterfaceC1769Sc {
    @Override // com.google.android.gms.internal.ads.InterfaceC1769Sc
    public final void C(String str) {
        Parcel parcelF3 = f3();
        parcelF3.writeString(str);
        d4(2, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1769Sc
    public final void e1(String str, String str2, Bundle bundle) {
        Parcel parcelF3 = f3();
        parcelF3.writeString(str);
        parcelF3.writeString(str2);
        AbstractC2857y5.c(parcelF3, bundle);
        d4(3, parcelF3);
    }
}

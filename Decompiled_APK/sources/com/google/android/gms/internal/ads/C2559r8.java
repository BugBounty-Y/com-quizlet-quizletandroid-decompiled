package com.google.android.gms.internal.ads;

import android.os.IBinder;
import android.os.Parcel;
import java.util.ArrayList;

/* renamed from: com.google.android.gms.internal.ads.r8, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2559r8 extends AbstractC2771w5 implements InterfaceC2645t8 {
    public C2559r8(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.ads.internal.formats.client.IAttributionInfo", 0);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2645t8
    public final ArrayList g() {
        Parcel parcelY3 = Y3(3, f3());
        ArrayList arrayList = parcelY3.readArrayList(AbstractC2857y5.a);
        parcelY3.recycle();
        return arrayList;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2645t8
    public final String h() {
        Parcel parcelY3 = Y3(2, f3());
        String string = parcelY3.readString();
        parcelY3.recycle();
        return string;
    }
}

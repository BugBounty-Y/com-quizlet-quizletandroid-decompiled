package com.google.android.gms.ads.internal.client;

import android.os.IBinder;
import android.os.Parcel;
import com.google.android.gms.internal.ads.AbstractC2771w5;
import com.google.android.gms.internal.ads.AbstractC2857y5;

/* renamed from: com.google.android.gms.ads.internal.client.o0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1611o0 extends AbstractC2771w5 implements InterfaceC1613p0 {
    public C1611o0(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.ads.internal.client.IOutOfContextTester", 0);
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1613p0
    public final void F2(String str, com.google.android.gms.dynamic.a aVar, com.google.android.gms.dynamic.a aVar2) {
        Parcel parcelF3 = f3();
        parcelF3.writeString(str);
        AbstractC2857y5.e(parcelF3, aVar);
        AbstractC2857y5.e(parcelF3, aVar2);
        d4(1, parcelF3);
    }
}

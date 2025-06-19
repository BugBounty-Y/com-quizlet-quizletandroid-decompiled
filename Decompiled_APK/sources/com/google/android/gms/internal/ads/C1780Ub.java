package com.google.android.gms.internal.ads;

import android.os.IBinder;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import com.google.android.gms.ads.internal.util.zzbb;

/* renamed from: com.google.android.gms.internal.ads.Ub, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1780Ub extends AbstractC2771w5 implements InterfaceC1792Wb {
    public C1780Ub(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.ads.internal.request.INonagonStreamingResponseListener", 0);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1792Wb
    public final void a2(ParcelFileDescriptor parcelFileDescriptor) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.c(parcelF3, parcelFileDescriptor);
        d4(1, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1792Wb
    public final void d1(zzbb zzbbVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.c(parcelF3, zzbbVar);
        d4(2, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1792Wb
    public final void m0(ParcelFileDescriptor parcelFileDescriptor, zzbvl zzbvlVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.c(parcelF3, parcelFileDescriptor);
        AbstractC2857y5.c(parcelF3, zzbvlVar);
        d4(3, parcelF3);
    }
}

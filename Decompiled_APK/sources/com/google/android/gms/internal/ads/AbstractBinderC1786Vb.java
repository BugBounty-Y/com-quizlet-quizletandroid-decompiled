package com.google.android.gms.internal.ads;

import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import com.google.android.gms.ads.internal.util.zzbb;

/* renamed from: com.google.android.gms.internal.ads.Vb, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractBinderC1786Vb extends AbstractBinderC2814x5 implements InterfaceC1792Wb {
    public AbstractBinderC1786Vb() {
        super("com.google.android.gms.ads.internal.request.INonagonStreamingResponseListener");
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        if (i == 1) {
            ParcelFileDescriptor parcelFileDescriptor = (ParcelFileDescriptor) AbstractC2857y5.a(parcel, ParcelFileDescriptor.CREATOR);
            AbstractC2857y5.b(parcel);
            a2(parcelFileDescriptor);
        } else if (i == 2) {
            zzbb zzbbVar = (zzbb) AbstractC2857y5.a(parcel, zzbb.CREATOR);
            AbstractC2857y5.b(parcel);
            d1(zzbbVar);
        } else {
            if (i != 3) {
                return false;
            }
            ParcelFileDescriptor parcelFileDescriptor2 = (ParcelFileDescriptor) AbstractC2857y5.a(parcel, ParcelFileDescriptor.CREATOR);
            zzbvl zzbvlVar = (zzbvl) AbstractC2857y5.a(parcel, zzbvl.CREATOR);
            AbstractC2857y5.b(parcel);
            m0(parcelFileDescriptor2, zzbvlVar);
        }
        parcel2.writeNoException();
        return true;
    }
}

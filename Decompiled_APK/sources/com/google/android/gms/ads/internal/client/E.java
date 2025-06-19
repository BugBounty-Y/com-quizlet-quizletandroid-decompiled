package com.google.android.gms.ads.internal.client;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import com.google.android.gms.ads.formats.AdManagerAdViewOptions;
import com.google.android.gms.internal.ads.AbstractC2771w5;
import com.google.android.gms.internal.ads.AbstractC2857y5;
import com.google.android.gms.internal.ads.N8;
import com.google.android.gms.internal.ads.P8;
import com.google.android.gms.internal.ads.S8;
import com.google.android.gms.internal.ads.U8;
import com.google.android.gms.internal.ads.zzbfv;

/* loaded from: classes2.dex */
public final class E extends AbstractC2771w5 implements G {
    public E(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.ads.internal.client.IAdLoaderBuilder", 0);
    }

    @Override // com.google.android.gms.ads.internal.client.G
    public final void J1(zzbfv zzbfvVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.c(parcelF3, zzbfvVar);
        d4(6, parcelF3);
    }

    @Override // com.google.android.gms.ads.internal.client.G
    public final void S3(AdManagerAdViewOptions adManagerAdViewOptions) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.c(parcelF3, adManagerAdViewOptions);
        d4(15, parcelF3);
    }

    @Override // com.google.android.gms.ads.internal.client.G
    public final void U2(InterfaceC1622x interfaceC1622x) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, interfaceC1622x);
        d4(2, parcelF3);
    }

    @Override // com.google.android.gms.ads.internal.client.G
    public final void i3(String str, P8 p8, N8 n8) {
        Parcel parcelF3 = f3();
        parcelF3.writeString(str);
        AbstractC2857y5.e(parcelF3, p8);
        AbstractC2857y5.e(parcelF3, n8);
        d4(5, parcelF3);
    }

    @Override // com.google.android.gms.ads.internal.client.G
    public final void m3(S8 s8, zzr zzrVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, s8);
        AbstractC2857y5.c(parcelF3, zzrVar);
        d4(8, parcelF3);
    }

    @Override // com.google.android.gms.ads.internal.client.G
    public final void o3(U8 u8) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, u8);
        d4(10, parcelF3);
    }

    @Override // com.google.android.gms.ads.internal.client.G
    public final D zze() {
        D b;
        Parcel parcelY3 = Y3(1, f3());
        IBinder strongBinder = parcelY3.readStrongBinder();
        if (strongBinder == null) {
            b = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.client.IAdLoader");
            b = iInterfaceQueryLocalInterface instanceof D ? (D) iInterfaceQueryLocalInterface : new B(strongBinder, "com.google.android.gms.ads.internal.client.IAdLoader", 0);
        }
        parcelY3.recycle();
        return b;
    }
}

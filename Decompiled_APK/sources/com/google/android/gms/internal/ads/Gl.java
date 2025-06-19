package com.google.android.gms.internal.ads;

import android.os.ParcelFileDescriptor;
import com.google.android.gms.ads.internal.util.zzbb;

/* loaded from: classes2.dex */
public final class Gl extends AbstractBinderC1786Vb {
    public final C2313ld a;
    public final zzbvl b;

    public Gl(C2313ld c2313ld, zzbvl zzbvlVar) {
        this.a = c2313ld;
        this.b = zzbvlVar;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1792Wb
    public final void a2(ParcelFileDescriptor parcelFileDescriptor) {
        this.a.c(new Nl(new ParcelFileDescriptor.AutoCloseInputStream(parcelFileDescriptor), this.b));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1792Wb
    public final void d1(zzbb zzbbVar) {
        zzbbVar.getClass();
        this.a.d(new com.google.android.gms.ads.internal.util.zzba(zzbbVar.a, zzbbVar.b));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1792Wb
    public final void m0(ParcelFileDescriptor parcelFileDescriptor, zzbvl zzbvlVar) {
        this.a.c(new Nl(new ParcelFileDescriptor.AutoCloseInputStream(parcelFileDescriptor), zzbvlVar));
    }
}

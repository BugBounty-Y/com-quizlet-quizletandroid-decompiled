package com.google.android.gms.internal.ads;

import android.os.ParcelFileDescriptor;
import com.google.android.gms.ads.internal.util.zzbb;

/* loaded from: classes2.dex */
public final class Fl extends AbstractBinderC1786Vb {
    public final /* synthetic */ Hl a;

    public Fl(Hl hl) {
        this.a = hl;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1792Wb
    public final void a2(ParcelFileDescriptor parcelFileDescriptor) {
        ParcelFileDescriptor.AutoCloseInputStream autoCloseInputStream = new ParcelFileDescriptor.AutoCloseInputStream(parcelFileDescriptor);
        Hl hl = this.a;
        hl.a.c(new Nl(autoCloseInputStream, hl.e));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1792Wb
    public final void d1(zzbb zzbbVar) {
        C2313ld c2313ld = this.a.a;
        zzbbVar.getClass();
        c2313ld.d(new com.google.android.gms.ads.internal.util.zzba(zzbbVar.a, zzbbVar.b));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1792Wb
    public final void m0(ParcelFileDescriptor parcelFileDescriptor, zzbvl zzbvlVar) {
        this.a.a.c(new Nl(new ParcelFileDescriptor.AutoCloseInputStream(parcelFileDescriptor), zzbvlVar));
    }
}

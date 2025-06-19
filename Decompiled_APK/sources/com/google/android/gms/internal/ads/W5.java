package com.google.android.gms.internal.ads;

import android.os.Parcel;
import com.google.android.gms.ads.internal.client.zze;

/* loaded from: classes2.dex */
public final class W5 extends AbstractBinderC2814x5 implements InterfaceC1953d6 {
    @Override // com.google.android.gms.internal.ads.InterfaceC1953d6
    public final void S(zze zzeVar) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1953d6
    public final void b() {
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        if (i != 1 && i != 2) {
            if (i == 3) {
                AbstractC2857y5.b(parcel);
            } else if (i != 4 && i != 5) {
                return false;
            }
        }
        parcel2.writeNoException();
        return true;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1953d6
    public final void f() {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1953d6
    public final void q() {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1953d6
    public final void zze() {
    }
}

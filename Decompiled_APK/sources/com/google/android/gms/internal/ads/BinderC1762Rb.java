package com.google.android.gms.internal.ads;

import android.os.Parcel;

/* renamed from: com.google.android.gms.internal.ads.Rb, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class BinderC1762Rb extends AbstractBinderC2814x5 {
    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        if (i != 1) {
            return false;
        }
        com.google.android.gms.ads.internal.j.C.h.h("FlagsAccessedBeforeInitialized", new C1756Qb("Flags were accessed before initialized."));
        parcel2.writeNoException();
        return true;
    }
}

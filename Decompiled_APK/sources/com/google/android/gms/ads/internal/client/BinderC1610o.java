package com.google.android.gms.ads.internal.client;

import android.os.Parcel;
import com.google.android.gms.internal.ads.AbstractBinderC2814x5;

/* renamed from: com.google.android.gms.ads.internal.client.o, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class BinderC1610o extends AbstractBinderC2814x5 implements InterfaceC1619u {
    public final InterfaceC1582a a;

    public BinderC1610o(InterfaceC1582a interfaceC1582a) {
        super("com.google.android.gms.ads.internal.client.IAdClickListener");
        this.a = interfaceC1582a;
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1619u
    public final void b() {
        this.a.onAdClicked();
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        if (i != 1) {
            return false;
        }
        b();
        parcel2.writeNoException();
        return true;
    }
}

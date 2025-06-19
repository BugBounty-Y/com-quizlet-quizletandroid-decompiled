package com.google.android.gms.internal.ads;

import android.os.Parcel;

/* renamed from: com.google.android.gms.internal.ads.zc, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class BinderC2913zc extends AbstractBinderC2814x5 implements InterfaceC2312lc {
    public final String a;
    public final int b;

    public BinderC2913zc(String str, int i) {
        super("com.google.android.gms.ads.internal.rewarded.client.IRewardItem");
        this.a = str;
        this.b = i;
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        if (i == 1) {
            parcel2.writeNoException();
            parcel2.writeString(this.a);
            return true;
        }
        if (i != 2) {
            return false;
        }
        parcel2.writeNoException();
        parcel2.writeInt(this.b);
        return true;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2312lc
    public final String f() {
        return this.a;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2312lc
    public final int zze() {
        return this.b;
    }
}

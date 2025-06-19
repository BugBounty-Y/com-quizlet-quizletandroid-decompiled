package com.google.android.gms.ads.internal.client;

import android.os.Parcel;
import com.google.android.gms.internal.ads.AbstractBinderC2814x5;
import com.google.android.gms.internal.ads.AbstractC2857y5;

/* renamed from: com.google.android.gms.ads.internal.client.j0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractBinderC1601j0 extends AbstractBinderC2814x5 implements InterfaceC1603k0 {
    public AbstractBinderC1601j0() {
        super("com.google.android.gms.ads.internal.client.IOnAdInspectorClosedListener");
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        if (i != 1) {
            return false;
        }
        zze zzeVar = (zze) AbstractC2857y5.a(parcel, zze.CREATOR);
        AbstractC2857y5.b(parcel);
        T1(zzeVar);
        parcel2.writeNoException();
        return true;
    }
}

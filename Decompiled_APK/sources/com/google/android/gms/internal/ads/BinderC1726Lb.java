package com.google.android.gms.internal.ads;

import android.os.Bundle;
import android.os.Parcel;

/* renamed from: com.google.android.gms.internal.ads.Lb, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class BinderC1726Lb extends AbstractBinderC2814x5 implements InterfaceC1769Sc {
    public final /* synthetic */ com.google.android.gms.ads.query.a a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public BinderC1726Lb(com.google.android.gms.ads.query.a aVar) {
        super("com.google.android.gms.ads.internal.signals.ISignalCallback");
        this.a = aVar;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1769Sc
    public final void C(String str) {
        this.a.a(str);
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        if (i == 1) {
            parcel.readString();
            parcel.readString();
            AbstractC2857y5.b(parcel);
        } else if (i == 2) {
            String string = parcel.readString();
            AbstractC2857y5.b(parcel);
            C(string);
        } else {
            if (i != 3) {
                return false;
            }
            String string2 = parcel.readString();
            String string3 = parcel.readString();
            Bundle bundle = (Bundle) AbstractC2857y5.a(parcel, Bundle.CREATOR);
            AbstractC2857y5.b(parcel);
            e1(string2, string3, bundle);
        }
        parcel2.writeNoException();
        return true;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1769Sc
    public final void e1(String str, String str2, Bundle bundle) {
        this.a.b(new androidx.appcompat.app.L(new androidx.emoji2.text.r(str), 20));
    }
}

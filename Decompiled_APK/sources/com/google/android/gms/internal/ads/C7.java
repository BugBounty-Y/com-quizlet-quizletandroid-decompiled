package com.google.android.gms.internal.ads;

import android.os.Parcel;
import android.view.View;

/* loaded from: classes2.dex */
public final class C7 extends AbstractBinderC2814x5 {
    public final com.google.android.gms.ads.internal.d a;
    public final String b;
    public final String c;

    public C7(com.google.android.gms.ads.internal.d dVar, String str, String str2) {
        super("com.google.android.gms.ads.internal.customrenderedad.client.ICustomRenderedAd");
        this.a = dVar;
        this.b = str;
        this.c = str2;
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        if (i == 1) {
            parcel2.writeNoException();
            parcel2.writeString(this.b);
            return true;
        }
        if (i == 2) {
            parcel2.writeNoException();
            parcel2.writeString(this.c);
            return true;
        }
        com.google.android.gms.ads.internal.d dVar = this.a;
        if (i == 3) {
            com.google.android.gms.dynamic.a aVarV3 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
            AbstractC2857y5.b(parcel);
            if (aVarV3 != null) {
                dVar.f((View) com.google.android.gms.dynamic.b.I3(aVarV3));
            }
            parcel2.writeNoException();
            return true;
        }
        if (i == 4) {
            dVar.zzb();
            parcel2.writeNoException();
            return true;
        }
        if (i != 5) {
            return false;
        }
        dVar.a();
        parcel2.writeNoException();
        return true;
    }
}

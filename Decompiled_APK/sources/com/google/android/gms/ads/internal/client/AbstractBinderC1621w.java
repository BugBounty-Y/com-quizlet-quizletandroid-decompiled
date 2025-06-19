package com.google.android.gms.ads.internal.client;

import android.os.Parcel;
import com.google.android.gms.internal.ads.AbstractBinderC2814x5;
import com.google.android.gms.internal.ads.AbstractC2857y5;

/* renamed from: com.google.android.gms.ads.internal.client.w, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractBinderC1621w extends AbstractBinderC2814x5 implements InterfaceC1622x {
    public AbstractBinderC1621w() {
        super("com.google.android.gms.ads.internal.client.IAdListener");
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        switch (i) {
            case 1:
                j();
                break;
            case 2:
                int i2 = parcel.readInt();
                AbstractC2857y5.b(parcel);
                u(i2);
                break;
            case 3:
                break;
            case 4:
                zzi();
                break;
            case 5:
                i();
                break;
            case 6:
                q();
                break;
            case 7:
                h();
                break;
            case 8:
                zze zzeVar = (zze) AbstractC2857y5.a(parcel, zze.CREATOR);
                AbstractC2857y5.b(parcel);
                r(zzeVar);
                break;
            case 9:
                t();
                break;
            default:
                return false;
        }
        parcel2.writeNoException();
        return true;
    }
}

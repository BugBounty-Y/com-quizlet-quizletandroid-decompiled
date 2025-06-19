package com.google.android.gms.internal.ads;

import android.os.Parcel;

/* renamed from: com.google.android.gms.internal.ads.ic, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractBinderC2185ic extends AbstractBinderC2814x5 implements InterfaceC2226jc {
    public AbstractBinderC2185ic() {
        super("com.google.android.gms.ads.internal.reward.mediation.client.IMediationRewardedVideoAdListener");
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        switch (i) {
            case 1:
                com.google.android.gms.dynamic.a aVarV3 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                M3(aVarV3);
                break;
            case 2:
                com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                parcel.readInt();
                AbstractC2857y5.b(parcel);
                c1();
                break;
            case 3:
                com.google.android.gms.dynamic.a aVarV32 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                H2(aVarV32);
                break;
            case 4:
                com.google.android.gms.dynamic.a aVarV33 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                O2(aVarV33);
                break;
            case 5:
                com.google.android.gms.dynamic.a aVarV34 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                V1(aVarV34);
                break;
            case 6:
                com.google.android.gms.dynamic.a aVarV35 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                t0(aVarV35);
                break;
            case 7:
                com.google.android.gms.dynamic.a aVarV36 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                zzbwj zzbwjVar = (zzbwj) AbstractC2857y5.a(parcel, zzbwj.CREATOR);
                AbstractC2857y5.b(parcel);
                G0(aVarV36, zzbwjVar);
                break;
            case 8:
                com.google.android.gms.dynamic.a aVarV37 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                zze(aVarV37);
                break;
            case 9:
                com.google.android.gms.dynamic.a aVarV38 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                int i2 = parcel.readInt();
                AbstractC2857y5.b(parcel);
                b2(aVarV38, i2);
                break;
            case 10:
                com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                R1();
                break;
            case 11:
                com.google.android.gms.dynamic.a aVarV39 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                L0(aVarV39);
                break;
            case 12:
                AbstractC2857y5.b(parcel);
                break;
            case 13:
                com.google.android.gms.dynamic.a aVarV310 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                D(aVarV310);
                break;
            default:
                return false;
        }
        parcel2.writeNoException();
        return true;
    }
}

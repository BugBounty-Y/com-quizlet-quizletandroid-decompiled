package com.google.android.gms.internal.ads;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import com.comscore.streaming.EventType;
import com.google.android.gms.ads.internal.client.zze;

/* renamed from: com.google.android.gms.internal.ads.Ba, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractBinderC1665Ba extends AbstractBinderC2814x5 implements InterfaceC1671Ca {
    public AbstractBinderC1665Ba() {
        super("com.google.android.gms.ads.internal.mediation.client.IMediationAdapterListener");
    }

    public static InterfaceC1671Ca e4(IBinder iBinder) {
        if (iBinder == null) {
            return null;
        }
        IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.ads.internal.mediation.client.IMediationAdapterListener");
        return iInterfaceQueryLocalInterface instanceof InterfaceC1671Ca ? (InterfaceC1671Ca) iInterfaceQueryLocalInterface : new C1659Aa(iBinder);
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        InterfaceC2312lc c2269kc;
        switch (i) {
            case 1:
                zze();
                break;
            case 2:
                f();
                break;
            case 3:
                int i2 = parcel.readInt();
                AbstractC2857y5.b(parcel);
                e(i2);
                break;
            case 4:
                m();
                break;
            case 5:
                o();
                break;
            case 6:
                v();
                break;
            case 7:
                IBinder strongBinder = parcel.readStrongBinder();
                if (strongBinder != null) {
                    strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.mediation.client.IMediationResponseMetadata");
                }
                AbstractC2857y5.b(parcel);
                break;
            case 8:
                l();
                break;
            case 9:
                String string = parcel.readString();
                String string2 = parcel.readString();
                AbstractC2857y5.b(parcel);
                T2(string, string2);
                break;
            case 10:
                IBinder strongBinder2 = parcel.readStrongBinder();
                if (strongBinder2 != null) {
                    boolean z = strongBinder2.queryLocalInterface("com.google.android.gms.ads.internal.formats.client.INativeCustomTemplateAd") instanceof J8;
                }
                parcel.readString();
                AbstractC2857y5.b(parcel);
                break;
            case 11:
                G();
                break;
            case 12:
                parcel.readString();
                AbstractC2857y5.b(parcel);
                break;
            case 13:
                P();
                break;
            case 14:
                zzbwj zzbwjVar = (zzbwj) AbstractC2857y5.a(parcel, zzbwj.CREATOR);
                AbstractC2857y5.b(parcel);
                o2(zzbwjVar);
                break;
            case 15:
                y();
                break;
            case 16:
                IBinder strongBinder3 = parcel.readStrongBinder();
                if (strongBinder3 == null) {
                    c2269kc = null;
                } else {
                    IInterface iInterfaceQueryLocalInterface = strongBinder3.queryLocalInterface("com.google.android.gms.ads.internal.rewarded.client.IRewardItem");
                    c2269kc = iInterfaceQueryLocalInterface instanceof InterfaceC2312lc ? (InterfaceC2312lc) iInterfaceQueryLocalInterface : new C2269kc(strongBinder3);
                }
                AbstractC2857y5.b(parcel);
                z0(c2269kc);
                break;
            case 17:
                int i3 = parcel.readInt();
                AbstractC2857y5.b(parcel);
                N2(i3);
                break;
            case 18:
                d();
                break;
            case 19:
                AbstractC2857y5.b(parcel);
                break;
            case 20:
                B();
                break;
            case 21:
                String string3 = parcel.readString();
                AbstractC2857y5.b(parcel);
                C0(string3);
                break;
            case EventType.WINDOW_STATE /* 22 */:
                int i4 = parcel.readInt();
                String string4 = parcel.readString();
                AbstractC2857y5.b(parcel);
                I0(i4, string4);
                break;
            case EventType.AUDIO /* 23 */:
                zze zzeVar = (zze) AbstractC2857y5.a(parcel, zze.CREATOR);
                AbstractC2857y5.b(parcel);
                S0(zzeVar);
                break;
            case EventType.VIDEO /* 24 */:
                zze zzeVar2 = (zze) AbstractC2857y5.a(parcel, zze.CREATOR);
                AbstractC2857y5.b(parcel);
                j2(zzeVar2);
                break;
            case EventType.SUBS /* 25 */:
                c();
                break;
            default:
                return false;
        }
        parcel2.writeNoException();
        return true;
    }
}

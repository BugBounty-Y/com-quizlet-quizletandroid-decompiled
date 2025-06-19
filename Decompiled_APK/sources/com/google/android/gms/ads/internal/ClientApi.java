package com.google.android.gms.ads.internal;

import android.app.Activity;
import android.content.Context;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.view.View;
import android.widget.FrameLayout;
import com.google.android.gms.ads.internal.client.G;
import com.google.android.gms.ads.internal.client.InterfaceC1585b0;
import com.google.android.gms.ads.internal.client.InterfaceC1613p0;
import com.google.android.gms.ads.internal.client.K;
import com.google.android.gms.ads.internal.client.S;
import com.google.android.gms.ads.internal.client.zzr;
import com.google.android.gms.ads.internal.overlay.AdOverlayInfoParcel;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.ads.dynamite.ModuleDescriptor;
import com.google.android.gms.internal.ads.AbstractBinderC2814x5;
import com.google.android.gms.internal.ads.AbstractC1795We;
import com.google.android.gms.internal.ads.AbstractC1981ds;
import com.google.android.gms.internal.ads.AbstractC2857y5;
import com.google.android.gms.internal.ads.BC;
import com.google.android.gms.internal.ads.BinderC2144hf;
import com.google.android.gms.internal.ads.BinderC2408nm;
import com.google.android.gms.internal.ads.BinderC2625sp;
import com.google.android.gms.internal.ads.BinderC2707ul;
import com.google.android.gms.internal.ads.BinderC2739va;
import com.google.android.gms.internal.ads.BinderC2842xr;
import com.google.android.gms.internal.ads.C1732Mb;
import com.google.android.gms.internal.ads.C1741Ne;
import com.google.android.gms.internal.ads.C1765Re;
import com.google.android.gms.internal.ads.C1801Xe;
import com.google.android.gms.internal.ads.C2668tp;
import com.google.android.gms.internal.ads.C2873yf;
import com.google.android.gms.internal.ads.C2904z9;
import com.google.android.gms.internal.ads.C8;
import com.google.android.gms.internal.ads.DC;
import com.google.android.gms.internal.ads.Hk;
import com.google.android.gms.internal.ads.Hn;
import com.google.android.gms.internal.ads.Ig;
import com.google.android.gms.internal.ads.InterfaceC1672Cb;
import com.google.android.gms.internal.ads.InterfaceC1787Vc;
import com.google.android.gms.internal.ads.InterfaceC2441oc;
import com.google.android.gms.internal.ads.InterfaceC2783wb;
import com.google.android.gms.internal.ads.InterfaceC2825xa;
import com.google.android.gms.internal.ads.Jn;
import com.google.android.gms.internal.ads.LA;
import com.google.android.gms.internal.ads.Ln;
import com.google.android.gms.internal.ads.Mm;
import com.google.android.gms.internal.ads.Ok;
import com.google.android.gms.internal.ads.On;
import com.google.android.gms.internal.ads.S4;
import com.google.android.gms.internal.ads.Sk;
import com.google.android.gms.internal.ads.Sp;
import com.google.android.gms.internal.ads.Tp;
import com.google.android.gms.internal.ads.ViewTreeObserverOnGlobalLayoutListenerC2060fj;
import com.google.android.gms.internal.ads.ViewTreeObserverOnGlobalLayoutListenerC2148hj;
import java.util.HashMap;

/* loaded from: classes2.dex */
public class ClientApi extends AbstractBinderC2814x5 implements S {
    public ClientApi() {
        super("com.google.android.gms.ads.internal.client.IClientApi");
    }

    @Override // com.google.android.gms.ads.internal.client.S
    public final InterfaceC1672Cb D(com.google.android.gms.dynamic.a aVar) {
        Activity activity = (Activity) com.google.android.gms.dynamic.b.I3(aVar);
        AdOverlayInfoParcel adOverlayInfoParcelA = AdOverlayInfoParcel.a(activity.getIntent());
        if (adOverlayInfoParcelA == null) {
            return new com.google.android.gms.ads.internal.overlay.d(4, activity);
        }
        int i = adOverlayInfoParcelA.k;
        return i != 1 ? i != 2 ? i != 3 ? i != 4 ? i != 5 ? new com.google.android.gms.ads.internal.overlay.d(4, activity) : new com.google.android.gms.ads.internal.overlay.d(0, activity) : new com.google.android.gms.ads.internal.overlay.b(activity, adOverlayInfoParcelA) : new com.google.android.gms.ads.internal.overlay.d(2, activity) : new com.google.android.gms.ads.internal.overlay.d(1, activity) : new com.google.android.gms.ads.internal.overlay.d(3, activity);
    }

    @Override // com.google.android.gms.ads.internal.client.S
    public final InterfaceC2783wb D1(com.google.android.gms.dynamic.a aVar, InterfaceC2825xa interfaceC2825xa, int i) {
        return (BinderC2408nm) C1765Re.b((Context) com.google.android.gms.dynamic.b.I3(aVar), interfaceC2825xa, i).H.zzb();
    }

    @Override // com.google.android.gms.ads.internal.client.S
    public final K F0(com.google.android.gms.dynamic.a aVar, zzr zzrVar, String str, InterfaceC2825xa interfaceC2825xa, int i) {
        Context context = (Context) com.google.android.gms.dynamic.b.I3(aVar);
        C1765Re c1765ReB = C1765Re.b(context, interfaceC2825xa, i);
        context.getClass();
        zzrVar.getClass();
        str.getClass();
        return (On) ((BC) new S4(c1765ReB.b, context, str, zzrVar).b).zzb();
    }

    @Override // com.google.android.gms.ads.internal.client.S
    public final InterfaceC1613p0 G2(com.google.android.gms.dynamic.a aVar, InterfaceC2825xa interfaceC2825xa, int i) {
        return (BinderC2707ul) C1765Re.b((Context) com.google.android.gms.dynamic.b.I3(aVar), interfaceC2825xa, i).t.zzb();
    }

    @Override // com.google.android.gms.ads.internal.client.S
    public final C8 P1(com.google.android.gms.dynamic.a aVar, com.google.android.gms.dynamic.a aVar2) {
        return new ViewTreeObserverOnGlobalLayoutListenerC2148hj((FrameLayout) com.google.android.gms.dynamic.b.I3(aVar), (FrameLayout) com.google.android.gms.dynamic.b.I3(aVar2));
    }

    @Override // com.google.android.gms.ads.internal.client.S
    public final InterfaceC1585b0 V2(com.google.android.gms.dynamic.a aVar, int i) {
        return (BinderC2144hf) C1765Re.b((Context) com.google.android.gms.dynamic.b.I3(aVar), null, i).y.zzb();
    }

    @Override // com.google.android.gms.ads.internal.client.S
    public final K a1(com.google.android.gms.dynamic.a aVar, zzr zzrVar, String str, InterfaceC2825xa interfaceC2825xa, int i) {
        Context context = (Context) com.google.android.gms.dynamic.b.I3(aVar);
        C1765Re c1765ReB = C1765Re.b(context, interfaceC2825xa, i);
        context.getClass();
        zzrVar.getClass();
        str.getClass();
        DC dcA = DC.a(context);
        DC dcA2 = DC.a(zzrVar);
        C1765Re c1765Re = c1765ReB.b;
        BC bcB = BC.b(new Ok(c1765Re.x, 16));
        C2668tp c2668tp = (C2668tp) BC.b(new Ig(dcA, c1765Re.c, dcA2, c1765Re.A, bcB, BC.b(LA.s), BC.b(AbstractC1795We.n))).zzb();
        Ln ln = (Ln) bcB.zzb();
        VersionInfoParcel versionInfoParcel = c1765Re.a.a;
        AbstractC1981ds.s(versionInfoParcel);
        return new Jn(context, zzrVar, str, c2668tp, ln, versionInfoParcel, (Hk) c1765Re.x.zzb());
    }

    @Override // com.google.android.gms.ads.internal.client.S
    public final G b1(com.google.android.gms.dynamic.a aVar, String str, InterfaceC2825xa interfaceC2825xa, int i) {
        Context context = (Context) com.google.android.gms.dynamic.b.I3(aVar);
        return new Hn(C1765Re.b(context, interfaceC2825xa, i), context, str);
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        C2904z9 c2904z9 = null;
        switch (i) {
            case 1:
                com.google.android.gms.dynamic.a aVarV3 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                zzr zzrVar = (zzr) AbstractC2857y5.a(parcel, zzr.CREATOR);
                String string = parcel.readString();
                InterfaceC2825xa interfaceC2825xaE4 = BinderC2739va.e4(parcel.readStrongBinder());
                int i2 = parcel.readInt();
                AbstractC2857y5.b(parcel);
                K kA1 = a1(aVarV3, zzrVar, string, interfaceC2825xaE4, i2);
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, kA1);
                return true;
            case 2:
                com.google.android.gms.dynamic.a aVarV32 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                zzr zzrVar2 = (zzr) AbstractC2857y5.a(parcel, zzr.CREATOR);
                String string2 = parcel.readString();
                InterfaceC2825xa interfaceC2825xaE42 = BinderC2739va.e4(parcel.readStrongBinder());
                int i3 = parcel.readInt();
                AbstractC2857y5.b(parcel);
                K kF0 = F0(aVarV32, zzrVar2, string2, interfaceC2825xaE42, i3);
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, kF0);
                return true;
            case 3:
                com.google.android.gms.dynamic.a aVarV33 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                String string3 = parcel.readString();
                InterfaceC2825xa interfaceC2825xaE43 = BinderC2739va.e4(parcel.readStrongBinder());
                int i4 = parcel.readInt();
                AbstractC2857y5.b(parcel);
                G gB1 = b1(aVarV33, string3, interfaceC2825xaE43, i4);
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, gB1);
                return true;
            case 4:
                com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                parcel2.writeNoException();
                parcel2.writeStrongBinder(null);
                return true;
            case 5:
                com.google.android.gms.dynamic.a aVarV34 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                com.google.android.gms.dynamic.a aVarV35 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                C8 c8P1 = P1(aVarV34, aVarV35);
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, c8P1);
                return true;
            case 6:
                com.google.android.gms.dynamic.a aVarV36 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                InterfaceC2825xa interfaceC2825xaE44 = BinderC2739va.e4(parcel.readStrongBinder());
                int i5 = parcel.readInt();
                AbstractC2857y5.b(parcel);
                Context context = (Context) com.google.android.gms.dynamic.b.I3(aVarV36);
                C1765Re c1765ReB = C1765Re.b(context, interfaceC2825xaE44, i5);
                context.getClass();
                Tp tp = (Tp) ((BC) new C1732Mb(c1765ReB.b, context, (String) null).b).zzb();
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, tp);
                return true;
            case 7:
                com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                parcel2.writeNoException();
                parcel2.writeStrongBinder(null);
                return true;
            case 8:
                com.google.android.gms.dynamic.a aVarV37 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                InterfaceC1672Cb interfaceC1672CbD = D(aVarV37);
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, interfaceC1672CbD);
                return true;
            case 9:
                com.google.android.gms.dynamic.a aVarV38 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                int i6 = parcel.readInt();
                AbstractC2857y5.b(parcel);
                InterfaceC1585b0 interfaceC1585b0V2 = V2(aVarV38, i6);
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, interfaceC1585b0V2);
                return true;
            case 10:
                com.google.android.gms.dynamic.a aVarV39 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                zzr zzrVar3 = (zzr) AbstractC2857y5.a(parcel, zzr.CREATOR);
                String string4 = parcel.readString();
                int i7 = parcel.readInt();
                AbstractC2857y5.b(parcel);
                K kJ1 = j1(aVarV39, zzrVar3, string4, i7);
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, kJ1);
                return true;
            case 11:
                com.google.android.gms.dynamic.a aVarV310 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                com.google.android.gms.dynamic.a aVarV311 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                com.google.android.gms.dynamic.a aVarV312 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                ViewTreeObserverOnGlobalLayoutListenerC2060fj viewTreeObserverOnGlobalLayoutListenerC2060fj = new ViewTreeObserverOnGlobalLayoutListenerC2060fj((View) com.google.android.gms.dynamic.b.I3(aVarV310), (HashMap) com.google.android.gms.dynamic.b.I3(aVarV311), (HashMap) com.google.android.gms.dynamic.b.I3(aVarV312));
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, viewTreeObserverOnGlobalLayoutListenerC2060fj);
                return true;
            case 12:
                com.google.android.gms.dynamic.a aVarV313 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                String string5 = parcel.readString();
                InterfaceC2825xa interfaceC2825xaE45 = BinderC2739va.e4(parcel.readStrongBinder());
                int i8 = parcel.readInt();
                AbstractC2857y5.b(parcel);
                InterfaceC2441oc interfaceC2441ocX2 = x2(aVarV313, string5, interfaceC2825xaE45, i8);
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, interfaceC2441ocX2);
                return true;
            case 13:
                com.google.android.gms.dynamic.a aVarV314 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                zzr zzrVar4 = (zzr) AbstractC2857y5.a(parcel, zzr.CREATOR);
                String string6 = parcel.readString();
                InterfaceC2825xa interfaceC2825xaE46 = BinderC2739va.e4(parcel.readStrongBinder());
                int i9 = parcel.readInt();
                AbstractC2857y5.b(parcel);
                K kV1 = v1(aVarV314, zzrVar4, string6, interfaceC2825xaE46, i9);
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, kV1);
                return true;
            case 14:
                com.google.android.gms.dynamic.a aVarV315 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                InterfaceC2825xa interfaceC2825xaE47 = BinderC2739va.e4(parcel.readStrongBinder());
                int i10 = parcel.readInt();
                AbstractC2857y5.b(parcel);
                InterfaceC1787Vc interfaceC1787VcU3 = u3(aVarV315, interfaceC2825xaE47, i10);
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, interfaceC1787VcU3);
                return true;
            case 15:
                com.google.android.gms.dynamic.a aVarV316 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                InterfaceC2825xa interfaceC2825xaE48 = BinderC2739va.e4(parcel.readStrongBinder());
                int i11 = parcel.readInt();
                AbstractC2857y5.b(parcel);
                InterfaceC2783wb interfaceC2783wbD1 = D1(aVarV316, interfaceC2825xaE48, i11);
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, interfaceC2783wbD1);
                return true;
            case 16:
                com.google.android.gms.dynamic.a aVarV317 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                InterfaceC2825xa interfaceC2825xaE49 = BinderC2739va.e4(parcel.readStrongBinder());
                int i12 = parcel.readInt();
                IBinder strongBinder = parcel.readStrongBinder();
                if (strongBinder != null) {
                    IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.h5.client.IH5AdsEventListener");
                    c2904z9 = iInterfaceQueryLocalInterface instanceof C2904z9 ? (C2904z9) iInterfaceQueryLocalInterface : new C2904z9(strongBinder, "com.google.android.gms.ads.internal.h5.client.IH5AdsEventListener", 0);
                }
                AbstractC2857y5.b(parcel);
                Context context2 = (Context) com.google.android.gms.dynamic.b.I3(aVarV317);
                C1765Re c1765ReB2 = C1765Re.b(context2, interfaceC2825xaE49, i12);
                context2.getClass();
                c2904z9.getClass();
                Sk sk = (Sk) new C1801Xe(c1765ReB2.b, context2, c2904z9).e.zzb();
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, sk);
                return true;
            case 17:
                com.google.android.gms.dynamic.a aVarV318 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                InterfaceC2825xa interfaceC2825xaE410 = BinderC2739va.e4(parcel.readStrongBinder());
                int i13 = parcel.readInt();
                AbstractC2857y5.b(parcel);
                InterfaceC1613p0 interfaceC1613p0G2 = G2(aVarV318, interfaceC2825xaE410, i13);
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, interfaceC1613p0G2);
                return true;
            case 18:
                com.google.android.gms.dynamic.a aVarV319 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                InterfaceC2825xa interfaceC2825xaE411 = BinderC2739va.e4(parcel.readStrongBinder());
                int i14 = parcel.readInt();
                AbstractC2857y5.b(parcel);
                BinderC2842xr binderC2842xr = (BinderC2842xr) C1765Re.b((Context) com.google.android.gms.dynamic.b.I3(aVarV319), interfaceC2825xaE411, i14).z.zzb();
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, binderC2842xr);
                return true;
            default:
                return false;
        }
    }

    @Override // com.google.android.gms.ads.internal.client.S
    public final K j1(com.google.android.gms.dynamic.a aVar, zzr zzrVar, String str, int i) {
        return new i((Context) com.google.android.gms.dynamic.b.I3(aVar), zzrVar, str, new VersionInfoParcel(ModuleDescriptor.MODULE_VERSION, i, true, false));
    }

    @Override // com.google.android.gms.ads.internal.client.S
    public final InterfaceC1787Vc u3(com.google.android.gms.dynamic.a aVar, InterfaceC2825xa interfaceC2825xa, int i) {
        return (com.google.android.gms.ads.nonagon.signalgeneration.i) C1765Re.b((Context) com.google.android.gms.dynamic.b.I3(aVar), interfaceC2825xa, i).K.zzb();
    }

    @Override // com.google.android.gms.ads.internal.client.S
    public final K v1(com.google.android.gms.dynamic.a aVar, zzr zzrVar, String str, InterfaceC2825xa interfaceC2825xa, int i) {
        Context context = (Context) com.google.android.gms.dynamic.b.I3(aVar);
        C1765Re c1765ReB = C1765Re.b(context, interfaceC2825xa, i);
        str.getClass();
        context.getClass();
        DC dcA = DC.a(context);
        DC dcA2 = DC.a(str);
        C1765Re c1765Re = c1765ReB.b;
        BC bc = c1765Re.E0;
        Mm mm = new Mm(dcA, bc, c1765Re.F0, 4);
        BC bcB = BC.b(new Ok(bc, 22));
        BC bc2 = c1765Re.c;
        DC dc = c1765Re.A;
        C1741Ne c1741Ne = c1765Re.j;
        return (BinderC2625sp) BC.b(new Ig(dc, dcA, dcA2, BC.b(new C2873yf(dcA, bc2, dc, mm, bcB, c1741Ne)), bcB, c1741Ne, c1765Re.x)).zzb();
    }

    @Override // com.google.android.gms.ads.internal.client.S
    public final InterfaceC2441oc x2(com.google.android.gms.dynamic.a aVar, String str, InterfaceC2825xa interfaceC2825xa, int i) {
        Context context = (Context) com.google.android.gms.dynamic.b.I3(aVar);
        C1765Re c1765ReB = C1765Re.b(context, interfaceC2825xa, i);
        context.getClass();
        return (Sp) ((BC) new C1732Mb(c1765ReB.b, context, str).c).zzb();
    }
}

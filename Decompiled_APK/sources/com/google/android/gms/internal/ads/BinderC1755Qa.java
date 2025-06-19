package com.google.android.gms.internal.ads;

import android.os.Bundle;
import android.os.Parcel;
import android.view.View;
import com.comscore.streaming.EventType;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/* renamed from: com.google.android.gms.internal.ads.Qa, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class BinderC1755Qa extends AbstractBinderC2814x5 implements InterfaceC1707Ia {
    public final com.google.ads.mediation.a a;

    public BinderC1755Qa(com.google.ads.mediation.a aVar) {
        super("com.google.android.gms.ads.internal.mediation.client.IUnifiedNativeAdMapper");
        this.a = aVar;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final boolean K() {
        return this.a.m;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final void a3(com.google.android.gms.dynamic.a aVar, com.google.android.gms.dynamic.a aVar2, com.google.android.gms.dynamic.a aVar3) {
        View view = (View) com.google.android.gms.dynamic.b.I3(aVar);
        this.a.getClass();
        if (com.google.android.gms.ads.formats.e.a.get(view) != null) {
            throw new ClassCastException();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final String c() {
        return this.a.h;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final List d() {
        ArrayList arrayList = this.a.b;
        ArrayList arrayList2 = new ArrayList();
        if (arrayList != null) {
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                C2903z8 c2903z8 = (C2903z8) it2.next();
                arrayList2.add(new BinderC2474p8(c2903z8.b, c2903z8.c, c2903z8.d, c2903z8.e, c2903z8.f));
            }
        }
        return arrayList2;
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        switch (i) {
            case 2:
                String str = this.a.a;
                parcel2.writeNoException();
                parcel2.writeString(str);
                return true;
            case 3:
                List listD = d();
                parcel2.writeNoException();
                parcel2.writeList(listD);
                return true;
            case 4:
                String str2 = this.a.c;
                parcel2.writeNoException();
                parcel2.writeString(str2);
                return true;
            case 5:
                InterfaceC2860y8 interfaceC2860y8K = k();
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, interfaceC2860y8K);
                return true;
            case 6:
                String str3 = this.a.e;
                parcel2.writeNoException();
                parcel2.writeString(str3);
                return true;
            case 7:
                String str4 = this.a.f;
                parcel2.writeNoException();
                parcel2.writeString(str4);
                return true;
            case 8:
                double dZze = zze();
                parcel2.writeNoException();
                parcel2.writeDouble(dZze);
                return true;
            case 9:
                String str5 = this.a.h;
                parcel2.writeNoException();
                parcel2.writeString(str5);
                return true;
            case 10:
                String str6 = this.a.i;
                parcel2.writeNoException();
                parcel2.writeString(str6);
                return true;
            case 11:
                com.google.android.gms.ads.internal.client.v0 v0VarI = i();
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, v0VarI);
                return true;
            case 12:
                parcel2.writeNoException();
                ClassLoader classLoader = AbstractC2857y5.a;
                parcel2.writeStrongBinder(null);
                return true;
            case 13:
                l();
                parcel2.writeNoException();
                ClassLoader classLoader2 = AbstractC2857y5.a;
                parcel2.writeStrongBinder(null);
                return true;
            case 14:
                m();
                parcel2.writeNoException();
                ClassLoader classLoader3 = AbstractC2857y5.a;
                parcel2.writeStrongBinder(null);
                return true;
            case 15:
                com.google.android.gms.dynamic.a aVarX = x();
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, aVarX);
                return true;
            case 16:
                Bundle bundle = this.a.l;
                parcel2.writeNoException();
                AbstractC2857y5.d(parcel2, bundle);
                return true;
            case 17:
                boolean z = this.a.m;
                parcel2.writeNoException();
                ClassLoader classLoader4 = AbstractC2857y5.a;
                parcel2.writeInt(z ? 1 : 0);
                return true;
            case 18:
                boolean z2 = this.a.n;
                parcel2.writeNoException();
                ClassLoader classLoader5 = AbstractC2857y5.a;
                parcel2.writeInt(z2 ? 1 : 0);
                return true;
            case 19:
                y();
                parcel2.writeNoException();
                return true;
            case 20:
                com.google.android.gms.dynamic.a aVarV3 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                u0(aVarV3);
                parcel2.writeNoException();
                return true;
            case 21:
                com.google.android.gms.dynamic.a aVarV32 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                com.google.android.gms.dynamic.a aVarV33 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                com.google.android.gms.dynamic.a aVarV34 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                a3(aVarV32, aVarV33, aVarV34);
                parcel2.writeNoException();
                return true;
            case EventType.WINDOW_STATE /* 22 */:
                com.google.android.gms.dynamic.a aVarV35 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                y1(aVarV35);
                parcel2.writeNoException();
                return true;
            case EventType.AUDIO /* 23 */:
                f();
                parcel2.writeNoException();
                parcel2.writeFloat(DefinitionKt.NO_Float_VALUE);
                return true;
            case EventType.VIDEO /* 24 */:
                g();
                parcel2.writeNoException();
                parcel2.writeFloat(DefinitionKt.NO_Float_VALUE);
                return true;
            case EventType.SUBS /* 25 */:
                h();
                parcel2.writeNoException();
                parcel2.writeFloat(DefinitionKt.NO_Float_VALUE);
                return true;
            default:
                return false;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final float f() {
        this.a.getClass();
        return DefinitionKt.NO_Float_VALUE;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final float g() {
        this.a.getClass();
        return DefinitionKt.NO_Float_VALUE;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final float h() {
        this.a.getClass();
        return DefinitionKt.NO_Float_VALUE;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final com.google.android.gms.ads.internal.client.v0 i() {
        com.google.android.gms.ads.internal.client.v0 v0Var;
        com.google.android.gms.ads.s sVar = this.a.j;
        if (sVar == null) {
            return null;
        }
        synchronized (sVar.a) {
            v0Var = sVar.b;
        }
        return v0Var;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final boolean j0() {
        return this.a.n;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final InterfaceC2860y8 k() {
        C2903z8 c2903z8 = this.a.d;
        if (c2903z8 != null) {
            return new BinderC2474p8(c2903z8.b, c2903z8.c, c2903z8.d, c2903z8.e, c2903z8.f);
        }
        return null;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final com.google.android.gms.dynamic.a l() {
        this.a.getClass();
        return null;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final com.google.android.gms.dynamic.a m() {
        this.a.getClass();
        return null;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final InterfaceC2645t8 n() {
        return null;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final String o() {
        return this.a.f;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final String p() {
        return this.a.c;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final String s() {
        return this.a.i;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final void u0(com.google.android.gms.dynamic.a aVar) {
        this.a.getClass();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final String w() {
        return this.a.e;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final com.google.android.gms.dynamic.a x() {
        Object obj = this.a.k;
        if (obj == null) {
            return null;
        }
        return new com.google.android.gms.dynamic.b(obj);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final void y() {
        this.a.getClass();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final void y1(com.google.android.gms.dynamic.a aVar) {
        this.a.getClass();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final String z() {
        return this.a.a;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final double zze() {
        Double d = this.a.g;
        if (d != null) {
            return d.doubleValue();
        }
        return -1.0d;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final Bundle zzi() {
        return this.a.l;
    }
}

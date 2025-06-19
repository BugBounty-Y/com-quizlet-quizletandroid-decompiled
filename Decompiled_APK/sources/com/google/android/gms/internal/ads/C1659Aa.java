package com.google.android.gms.internal.ads;

import android.os.IBinder;
import android.os.Parcel;
import com.google.android.gms.ads.internal.client.zze;

/* renamed from: com.google.android.gms.internal.ads.Aa, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1659Aa extends AbstractC2771w5 implements InterfaceC1671Ca {
    public C1659Aa(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.ads.internal.mediation.client.IMediationAdapterListener", 0);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void B() {
        d4(20, f3());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void C0(String str) {
        Parcel parcelF3 = f3();
        parcelF3.writeString(str);
        d4(21, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void G() {
        d4(11, f3());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void I0(int i, String str) {
        Parcel parcelF3 = f3();
        parcelF3.writeInt(i);
        parcelF3.writeString(str);
        d4(22, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void N2(int i) {
        throw null;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void P() {
        d4(13, f3());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void S0(zze zzeVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.c(parcelF3, zzeVar);
        d4(23, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void T2(String str, String str2) {
        Parcel parcelF3 = f3();
        parcelF3.writeString(str);
        parcelF3.writeString(str2);
        d4(9, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void c() {
        d4(25, f3());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void d() {
        d4(18, f3());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void e(int i) {
        Parcel parcelF3 = f3();
        parcelF3.writeInt(i);
        d4(3, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void f() {
        d4(2, f3());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void j2(zze zzeVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.c(parcelF3, zzeVar);
        d4(24, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void l() {
        d4(8, f3());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void m() {
        d4(4, f3());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void o() {
        d4(5, f3());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void o2(zzbwj zzbwjVar) {
        throw null;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void v() {
        d4(6, f3());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void w1(J8 j8, String str) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, j8);
        parcelF3.writeString(str);
        d4(10, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void y() {
        d4(15, f3());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void z0(InterfaceC2312lc interfaceC2312lc) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, interfaceC2312lc);
        d4(16, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void zze() {
        d4(1, f3());
    }
}

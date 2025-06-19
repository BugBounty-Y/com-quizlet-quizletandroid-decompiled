package com.google.android.gms.measurement.internal;

import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import com.google.android.gms.internal.ads.AbstractC2771w5;
import com.google.android.gms.internal.measurement.AbstractC3081y;
import java.util.ArrayList;
import java.util.List;

/* renamed from: com.google.android.gms.measurement.internal.u, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3895u extends AbstractC2771w5 implements InterfaceC3897v {
    public C3895u(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.measurement.internal.IMeasurementService", 4);
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final void C1(zzr zzrVar) {
        Parcel parcelF3 = f3();
        AbstractC3081y.c(parcelF3, zzrVar);
        v3(26, parcelF3);
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final void C3(zzr zzrVar) {
        Parcel parcelF3 = f3();
        AbstractC3081y.c(parcelF3, zzrVar);
        v3(27, parcelF3);
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final void E3(zzr zzrVar, zzag zzagVar) {
        Parcel parcelF3 = f3();
        AbstractC3081y.c(parcelF3, zzrVar);
        AbstractC3081y.c(parcelF3, zzagVar);
        v3(30, parcelF3);
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final void M2(zzr zzrVar, zzpc zzpcVar, InterfaceC3905z interfaceC3905z) {
        Parcel parcelF3 = f3();
        AbstractC3081y.c(parcelF3, zzrVar);
        AbstractC3081y.c(parcelF3, zzpcVar);
        AbstractC3081y.d(parcelF3, interfaceC3905z);
        v3(29, parcelF3);
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final ArrayList N0(zzr zzrVar, boolean z) {
        Parcel parcelF3 = f3();
        AbstractC3081y.c(parcelF3, zzrVar);
        parcelF3.writeInt(1);
        Parcel parcelP3 = p3(7, parcelF3);
        ArrayList arrayListCreateTypedArrayList = parcelP3.createTypedArrayList(zzqb.CREATOR);
        parcelP3.recycle();
        return arrayListCreateTypedArrayList;
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final List P0(String str, String str2, boolean z, zzr zzrVar) {
        Parcel parcelF3 = f3();
        parcelF3.writeString(str);
        parcelF3.writeString(str2);
        ClassLoader classLoader = AbstractC3081y.a;
        parcelF3.writeInt(z ? 1 : 0);
        AbstractC3081y.c(parcelF3, zzrVar);
        Parcel parcelP3 = p3(14, parcelF3);
        ArrayList arrayListCreateTypedArrayList = parcelP3.createTypedArrayList(zzqb.CREATOR);
        parcelP3.recycle();
        return arrayListCreateTypedArrayList;
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final byte[] P2(zzbh zzbhVar, String str) {
        Parcel parcelF3 = f3();
        AbstractC3081y.c(parcelF3, zzbhVar);
        parcelF3.writeString(str);
        Parcel parcelP3 = p3(9, parcelF3);
        byte[] bArrCreateByteArray = parcelP3.createByteArray();
        parcelP3.recycle();
        return bArrCreateByteArray;
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final void Q2(zzai zzaiVar, zzr zzrVar) {
        Parcel parcelF3 = f3();
        AbstractC3081y.c(parcelF3, zzaiVar);
        AbstractC3081y.c(parcelF3, zzrVar);
        v3(12, parcelF3);
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final zzap Q3(zzr zzrVar) {
        Parcel parcelF3 = f3();
        AbstractC3081y.c(parcelF3, zzrVar);
        Parcel parcelP3 = p3(21, parcelF3);
        zzap zzapVar = (zzap) AbstractC3081y.a(parcelP3, zzap.CREATOR);
        parcelP3.recycle();
        return zzapVar;
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final void R3(zzr zzrVar) {
        Parcel parcelF3 = f3();
        AbstractC3081y.c(parcelF3, zzrVar);
        v3(20, parcelF3);
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final List T3(String str, String str2, zzr zzrVar) {
        Parcel parcelF3 = f3();
        parcelF3.writeString(str);
        parcelF3.writeString(str2);
        AbstractC3081y.c(parcelF3, zzrVar);
        Parcel parcelP3 = p3(16, parcelF3);
        ArrayList arrayListCreateTypedArrayList = parcelP3.createTypedArrayList(zzai.CREATOR);
        parcelP3.recycle();
        return arrayListCreateTypedArrayList;
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final void X1(zzr zzrVar) {
        Parcel parcelF3 = f3();
        AbstractC3081y.c(parcelF3, zzrVar);
        v3(6, parcelF3);
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final void X2(zzqb zzqbVar, zzr zzrVar) {
        Parcel parcelF3 = f3();
        AbstractC3081y.c(parcelF3, zzqbVar);
        AbstractC3081y.c(parcelF3, zzrVar);
        v3(2, parcelF3);
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final List Y1(String str, String str2, String str3, boolean z) {
        Parcel parcelF3 = f3();
        parcelF3.writeString(null);
        parcelF3.writeString(str2);
        parcelF3.writeString(str3);
        ClassLoader classLoader = AbstractC3081y.a;
        parcelF3.writeInt(z ? 1 : 0);
        Parcel parcelP3 = p3(15, parcelF3);
        ArrayList arrayListCreateTypedArrayList = parcelP3.createTypedArrayList(zzqb.CREATOR);
        parcelP3.recycle();
        return arrayListCreateTypedArrayList;
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final void Z3(long j, String str, String str2, String str3) {
        Parcel parcelF3 = f3();
        parcelF3.writeLong(j);
        parcelF3.writeString(str);
        parcelF3.writeString(str2);
        parcelF3.writeString(str3);
        v3(10, parcelF3);
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final void g1(Bundle bundle, zzr zzrVar) {
        Parcel parcelF3 = f3();
        AbstractC3081y.c(parcelF3, bundle);
        AbstractC3081y.c(parcelF3, zzrVar);
        v3(19, parcelF3);
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final void g2(zzr zzrVar, Bundle bundle, InterfaceC3901x interfaceC3901x) {
        Parcel parcelF3 = f3();
        AbstractC3081y.c(parcelF3, zzrVar);
        AbstractC3081y.c(parcelF3, bundle);
        AbstractC3081y.d(parcelF3, interfaceC3901x);
        v3(31, parcelF3);
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final void h2(zzr zzrVar) {
        Parcel parcelF3 = f3();
        AbstractC3081y.c(parcelF3, zzrVar);
        v3(4, parcelF3);
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final void k3(zzr zzrVar) {
        Parcel parcelF3 = f3();
        AbstractC3081y.c(parcelF3, zzrVar);
        v3(25, parcelF3);
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final String u2(zzr zzrVar) {
        Parcel parcelF3 = f3();
        AbstractC3081y.c(parcelF3, zzrVar);
        Parcel parcelP3 = p3(11, parcelF3);
        String string = parcelP3.readString();
        parcelP3.recycle();
        return string;
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final void w0(zzr zzrVar) {
        Parcel parcelF3 = f3();
        AbstractC3081y.c(parcelF3, zzrVar);
        v3(18, parcelF3);
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final void y0(zzbh zzbhVar, zzr zzrVar) {
        Parcel parcelF3 = f3();
        AbstractC3081y.c(parcelF3, zzbhVar);
        AbstractC3081y.c(parcelF3, zzrVar);
        v3(1, parcelF3);
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final List z1(String str, String str2, String str3) {
        Parcel parcelF3 = f3();
        parcelF3.writeString(null);
        parcelF3.writeString(str2);
        parcelF3.writeString(str3);
        Parcel parcelP3 = p3(17, parcelF3);
        ArrayList arrayListCreateTypedArrayList = parcelP3.createTypedArrayList(zzai.CREATOR);
        parcelP3.recycle();
        return arrayListCreateTypedArrayList;
    }
}

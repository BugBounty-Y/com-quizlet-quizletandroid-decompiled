package com.google.android.gms.internal.measurement;

import android.os.Bundle;
import android.os.Parcel;
import com.google.android.gms.internal.ads.AbstractC2771w5;

/* loaded from: classes2.dex */
public final class H extends AbstractC2771w5 implements J {
    @Override // com.google.android.gms.internal.measurement.J
    public final void beginAdUnitExposure(String str, long j) {
        Parcel parcelF3 = f3();
        parcelF3.writeString(str);
        parcelF3.writeLong(j);
        v3(23, parcelF3);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public final void clearConditionalUserProperty(String str, String str2, Bundle bundle) {
        Parcel parcelF3 = f3();
        parcelF3.writeString(str);
        parcelF3.writeString(str2);
        AbstractC3081y.c(parcelF3, bundle);
        v3(9, parcelF3);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public final void endAdUnitExposure(String str, long j) {
        Parcel parcelF3 = f3();
        parcelF3.writeString(str);
        parcelF3.writeLong(j);
        v3(24, parcelF3);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public final void generateEventId(L l) {
        Parcel parcelF3 = f3();
        AbstractC3081y.d(parcelF3, l);
        v3(22, parcelF3);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public final void getCachedAppInstanceId(L l) {
        Parcel parcelF3 = f3();
        AbstractC3081y.d(parcelF3, l);
        v3(19, parcelF3);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public final void getConditionalUserProperties(String str, String str2, L l) {
        Parcel parcelF3 = f3();
        parcelF3.writeString(str);
        parcelF3.writeString(str2);
        AbstractC3081y.d(parcelF3, l);
        v3(10, parcelF3);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public final void getCurrentScreenClass(L l) {
        Parcel parcelF3 = f3();
        AbstractC3081y.d(parcelF3, l);
        v3(17, parcelF3);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public final void getCurrentScreenName(L l) {
        Parcel parcelF3 = f3();
        AbstractC3081y.d(parcelF3, l);
        v3(16, parcelF3);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public final void getGmpAppId(L l) {
        Parcel parcelF3 = f3();
        AbstractC3081y.d(parcelF3, l);
        v3(21, parcelF3);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public final void getMaxUserProperties(String str, L l) {
        Parcel parcelF3 = f3();
        parcelF3.writeString(str);
        AbstractC3081y.d(parcelF3, l);
        v3(6, parcelF3);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public final void getUserProperties(String str, String str2, boolean z, L l) {
        Parcel parcelF3 = f3();
        parcelF3.writeString(str);
        parcelF3.writeString(str2);
        ClassLoader classLoader = AbstractC3081y.a;
        parcelF3.writeInt(z ? 1 : 0);
        AbstractC3081y.d(parcelF3, l);
        v3(5, parcelF3);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public final void initialize(com.google.android.gms.dynamic.a aVar, zzdh zzdhVar, long j) {
        Parcel parcelF3 = f3();
        AbstractC3081y.d(parcelF3, aVar);
        AbstractC3081y.c(parcelF3, zzdhVar);
        parcelF3.writeLong(j);
        v3(1, parcelF3);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public final void logEvent(String str, String str2, Bundle bundle, boolean z, boolean z2, long j) {
        Parcel parcelF3 = f3();
        parcelF3.writeString(str);
        parcelF3.writeString(str2);
        AbstractC3081y.c(parcelF3, bundle);
        parcelF3.writeInt(z ? 1 : 0);
        parcelF3.writeInt(z2 ? 1 : 0);
        parcelF3.writeLong(j);
        v3(2, parcelF3);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public final void logHealthData(int i, String str, com.google.android.gms.dynamic.a aVar, com.google.android.gms.dynamic.a aVar2, com.google.android.gms.dynamic.a aVar3) {
        Parcel parcelF3 = f3();
        parcelF3.writeInt(5);
        parcelF3.writeString("Error with data collection. Data lost.");
        AbstractC3081y.d(parcelF3, aVar);
        AbstractC3081y.d(parcelF3, aVar2);
        AbstractC3081y.d(parcelF3, aVar3);
        v3(33, parcelF3);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public final void onActivityCreatedByScionActivityInfo(zzdj zzdjVar, Bundle bundle, long j) {
        Parcel parcelF3 = f3();
        AbstractC3081y.c(parcelF3, zzdjVar);
        AbstractC3081y.c(parcelF3, bundle);
        parcelF3.writeLong(j);
        v3(53, parcelF3);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public final void onActivityDestroyedByScionActivityInfo(zzdj zzdjVar, long j) {
        Parcel parcelF3 = f3();
        AbstractC3081y.c(parcelF3, zzdjVar);
        parcelF3.writeLong(j);
        v3(54, parcelF3);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public final void onActivityPausedByScionActivityInfo(zzdj zzdjVar, long j) {
        Parcel parcelF3 = f3();
        AbstractC3081y.c(parcelF3, zzdjVar);
        parcelF3.writeLong(j);
        v3(55, parcelF3);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public final void onActivityResumedByScionActivityInfo(zzdj zzdjVar, long j) {
        Parcel parcelF3 = f3();
        AbstractC3081y.c(parcelF3, zzdjVar);
        parcelF3.writeLong(j);
        v3(56, parcelF3);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public final void onActivitySaveInstanceStateByScionActivityInfo(zzdj zzdjVar, L l, long j) {
        Parcel parcelF3 = f3();
        AbstractC3081y.c(parcelF3, zzdjVar);
        AbstractC3081y.d(parcelF3, l);
        parcelF3.writeLong(j);
        v3(57, parcelF3);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public final void onActivityStartedByScionActivityInfo(zzdj zzdjVar, long j) {
        Parcel parcelF3 = f3();
        AbstractC3081y.c(parcelF3, zzdjVar);
        parcelF3.writeLong(j);
        v3(51, parcelF3);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public final void onActivityStoppedByScionActivityInfo(zzdj zzdjVar, long j) {
        Parcel parcelF3 = f3();
        AbstractC3081y.c(parcelF3, zzdjVar);
        parcelF3.writeLong(j);
        v3(52, parcelF3);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public final void performAction(Bundle bundle, L l, long j) {
        Parcel parcelF3 = f3();
        AbstractC3081y.c(parcelF3, bundle);
        AbstractC3081y.d(parcelF3, l);
        parcelF3.writeLong(j);
        v3(32, parcelF3);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public final void registerOnMeasurementEventListener(P p) {
        Parcel parcelF3 = f3();
        AbstractC3081y.d(parcelF3, p);
        v3(35, parcelF3);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public final void retrieveAndUploadBatches(N n) {
        Parcel parcelF3 = f3();
        AbstractC3081y.d(parcelF3, n);
        v3(58, parcelF3);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public final void setConditionalUserProperty(Bundle bundle, long j) {
        Parcel parcelF3 = f3();
        AbstractC3081y.c(parcelF3, bundle);
        parcelF3.writeLong(j);
        v3(8, parcelF3);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public final void setCurrentScreenByScionActivityInfo(zzdj zzdjVar, String str, String str2, long j) {
        Parcel parcelF3 = f3();
        AbstractC3081y.c(parcelF3, zzdjVar);
        parcelF3.writeString(str);
        parcelF3.writeString(str2);
        parcelF3.writeLong(j);
        v3(50, parcelF3);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public final void setDataCollectionEnabled(boolean z) {
        throw null;
    }

    @Override // com.google.android.gms.internal.measurement.J
    public final void setEventInterceptor(P p) {
        Parcel parcelF3 = f3();
        AbstractC3081y.d(parcelF3, p);
        v3(34, parcelF3);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public final void setUserId(String str, long j) {
        Parcel parcelF3 = f3();
        parcelF3.writeString(str);
        parcelF3.writeLong(j);
        v3(7, parcelF3);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public final void setUserProperty(String str, String str2, com.google.android.gms.dynamic.a aVar, boolean z, long j) {
        Parcel parcelF3 = f3();
        parcelF3.writeString(str);
        parcelF3.writeString(str2);
        AbstractC3081y.d(parcelF3, aVar);
        parcelF3.writeInt(1);
        parcelF3.writeLong(j);
        v3(4, parcelF3);
    }
}

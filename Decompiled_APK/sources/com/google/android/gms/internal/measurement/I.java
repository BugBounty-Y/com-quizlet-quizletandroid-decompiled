package com.google.android.gms.internal.measurement;

import android.content.Intent;
import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import com.appsflyer.attribution.RequestError;
import com.comscore.streaming.EventType;
import java.util.HashMap;

/* loaded from: classes2.dex */
public abstract class I extends AbstractBinderC3076x implements J {
    public static J asInterface(IBinder iBinder) {
        if (iBinder == null) {
            return null;
        }
        IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.measurement.api.internal.IAppMeasurementDynamiteService");
        return iInterfaceQueryLocalInterface instanceof J ? (J) iInterfaceQueryLocalInterface : new H(iBinder, "com.google.android.gms.measurement.api.internal.IAppMeasurementDynamiteService", 4);
    }

    @Override // com.google.android.gms.internal.measurement.AbstractBinderC3076x
    public final boolean V(int i, Parcel parcel, Parcel parcel2) {
        boolean z;
        L k = null;
        N m = null;
        L k2 = null;
        L k3 = null;
        L k4 = null;
        L k5 = null;
        P o = null;
        P o2 = null;
        P o3 = null;
        L k6 = null;
        L k7 = null;
        L k8 = null;
        L k9 = null;
        L k10 = null;
        L k11 = null;
        S q = null;
        L k12 = null;
        L k13 = null;
        L k14 = null;
        L k15 = null;
        L k16 = null;
        switch (i) {
            case 1:
                com.google.android.gms.dynamic.a aVarV3 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                zzdh zzdhVar = (zzdh) AbstractC3081y.a(parcel, zzdh.CREATOR);
                long j = parcel.readLong();
                AbstractC3081y.b(parcel);
                initialize(aVarV3, zzdhVar, j);
                break;
            case 2:
                String string = parcel.readString();
                String string2 = parcel.readString();
                Bundle bundle = (Bundle) AbstractC3081y.a(parcel, Bundle.CREATOR);
                if (parcel.readInt() != 0) {
                    z = false;
                    z = true;
                } else {
                    z = false;
                }
                boolean z2 = parcel.readInt() != 0 ? true : z;
                long j2 = parcel.readLong();
                AbstractC3081y.b(parcel);
                logEvent(string, string2, bundle, z, z2, j2);
                break;
            case 3:
                String string3 = parcel.readString();
                String string4 = parcel.readString();
                Bundle bundle2 = (Bundle) AbstractC3081y.a(parcel, Bundle.CREATOR);
                IBinder strongBinder = parcel.readStrongBinder();
                if (strongBinder != null) {
                    IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.measurement.api.internal.IBundleReceiver");
                    k = iInterfaceQueryLocalInterface instanceof L ? (L) iInterfaceQueryLocalInterface : new K(strongBinder);
                }
                L l = k;
                long j3 = parcel.readLong();
                AbstractC3081y.b(parcel);
                logEventAndBundle(string3, string4, bundle2, l, j3);
                break;
            case 4:
                String string5 = parcel.readString();
                String string6 = parcel.readString();
                com.google.android.gms.dynamic.a aVarV32 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                ClassLoader classLoader = AbstractC3081y.a;
                z = parcel.readInt() != 0;
                long j4 = parcel.readLong();
                AbstractC3081y.b(parcel);
                setUserProperty(string5, string6, aVarV32, z, j4);
                break;
            case 5:
                String string7 = parcel.readString();
                String string8 = parcel.readString();
                ClassLoader classLoader2 = AbstractC3081y.a;
                z = parcel.readInt() != 0;
                IBinder strongBinder2 = parcel.readStrongBinder();
                if (strongBinder2 != null) {
                    IInterface iInterfaceQueryLocalInterface2 = strongBinder2.queryLocalInterface("com.google.android.gms.measurement.api.internal.IBundleReceiver");
                    k16 = iInterfaceQueryLocalInterface2 instanceof L ? (L) iInterfaceQueryLocalInterface2 : new K(strongBinder2);
                }
                AbstractC3081y.b(parcel);
                getUserProperties(string7, string8, z, k16);
                break;
            case 6:
                String string9 = parcel.readString();
                IBinder strongBinder3 = parcel.readStrongBinder();
                if (strongBinder3 != null) {
                    IInterface iInterfaceQueryLocalInterface3 = strongBinder3.queryLocalInterface("com.google.android.gms.measurement.api.internal.IBundleReceiver");
                    k15 = iInterfaceQueryLocalInterface3 instanceof L ? (L) iInterfaceQueryLocalInterface3 : new K(strongBinder3);
                }
                AbstractC3081y.b(parcel);
                getMaxUserProperties(string9, k15);
                break;
            case 7:
                String string10 = parcel.readString();
                long j5 = parcel.readLong();
                AbstractC3081y.b(parcel);
                setUserId(string10, j5);
                break;
            case 8:
                Bundle bundle3 = (Bundle) AbstractC3081y.a(parcel, Bundle.CREATOR);
                long j6 = parcel.readLong();
                AbstractC3081y.b(parcel);
                setConditionalUserProperty(bundle3, j6);
                break;
            case 9:
                String string11 = parcel.readString();
                String string12 = parcel.readString();
                Bundle bundle4 = (Bundle) AbstractC3081y.a(parcel, Bundle.CREATOR);
                AbstractC3081y.b(parcel);
                clearConditionalUserProperty(string11, string12, bundle4);
                break;
            case 10:
                String string13 = parcel.readString();
                String string14 = parcel.readString();
                IBinder strongBinder4 = parcel.readStrongBinder();
                if (strongBinder4 != null) {
                    IInterface iInterfaceQueryLocalInterface4 = strongBinder4.queryLocalInterface("com.google.android.gms.measurement.api.internal.IBundleReceiver");
                    k14 = iInterfaceQueryLocalInterface4 instanceof L ? (L) iInterfaceQueryLocalInterface4 : new K(strongBinder4);
                }
                AbstractC3081y.b(parcel);
                getConditionalUserProperties(string13, string14, k14);
                break;
            case 11:
                ClassLoader classLoader3 = AbstractC3081y.a;
                z = parcel.readInt() != 0;
                long j7 = parcel.readLong();
                AbstractC3081y.b(parcel);
                setMeasurementEnabled(z, j7);
                break;
            case 12:
                long j8 = parcel.readLong();
                AbstractC3081y.b(parcel);
                resetAnalyticsData(j8);
                break;
            case 13:
                long j9 = parcel.readLong();
                AbstractC3081y.b(parcel);
                setMinimumSessionDuration(j9);
                break;
            case 14:
                long j10 = parcel.readLong();
                AbstractC3081y.b(parcel);
                setSessionTimeoutDuration(j10);
                break;
            case 15:
                com.google.android.gms.dynamic.a aVarV33 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                String string15 = parcel.readString();
                String string16 = parcel.readString();
                long j11 = parcel.readLong();
                AbstractC3081y.b(parcel);
                setCurrentScreen(aVarV33, string15, string16, j11);
                break;
            case 16:
                IBinder strongBinder5 = parcel.readStrongBinder();
                if (strongBinder5 != null) {
                    IInterface iInterfaceQueryLocalInterface5 = strongBinder5.queryLocalInterface("com.google.android.gms.measurement.api.internal.IBundleReceiver");
                    k13 = iInterfaceQueryLocalInterface5 instanceof L ? (L) iInterfaceQueryLocalInterface5 : new K(strongBinder5);
                }
                AbstractC3081y.b(parcel);
                getCurrentScreenName(k13);
                break;
            case 17:
                IBinder strongBinder6 = parcel.readStrongBinder();
                if (strongBinder6 != null) {
                    IInterface iInterfaceQueryLocalInterface6 = strongBinder6.queryLocalInterface("com.google.android.gms.measurement.api.internal.IBundleReceiver");
                    k12 = iInterfaceQueryLocalInterface6 instanceof L ? (L) iInterfaceQueryLocalInterface6 : new K(strongBinder6);
                }
                AbstractC3081y.b(parcel);
                getCurrentScreenClass(k12);
                break;
            case 18:
                IBinder strongBinder7 = parcel.readStrongBinder();
                if (strongBinder7 != null) {
                    IInterface iInterfaceQueryLocalInterface7 = strongBinder7.queryLocalInterface("com.google.android.gms.measurement.api.internal.IStringProvider");
                    q = iInterfaceQueryLocalInterface7 instanceof S ? (S) iInterfaceQueryLocalInterface7 : new Q(strongBinder7, "com.google.android.gms.measurement.api.internal.IStringProvider", 4);
                }
                AbstractC3081y.b(parcel);
                setInstanceIdProvider(q);
                break;
            case 19:
                IBinder strongBinder8 = parcel.readStrongBinder();
                if (strongBinder8 != null) {
                    IInterface iInterfaceQueryLocalInterface8 = strongBinder8.queryLocalInterface("com.google.android.gms.measurement.api.internal.IBundleReceiver");
                    k11 = iInterfaceQueryLocalInterface8 instanceof L ? (L) iInterfaceQueryLocalInterface8 : new K(strongBinder8);
                }
                AbstractC3081y.b(parcel);
                getCachedAppInstanceId(k11);
                break;
            case 20:
                IBinder strongBinder9 = parcel.readStrongBinder();
                if (strongBinder9 != null) {
                    IInterface iInterfaceQueryLocalInterface9 = strongBinder9.queryLocalInterface("com.google.android.gms.measurement.api.internal.IBundleReceiver");
                    k10 = iInterfaceQueryLocalInterface9 instanceof L ? (L) iInterfaceQueryLocalInterface9 : new K(strongBinder9);
                }
                AbstractC3081y.b(parcel);
                getAppInstanceId(k10);
                break;
            case 21:
                IBinder strongBinder10 = parcel.readStrongBinder();
                if (strongBinder10 != null) {
                    IInterface iInterfaceQueryLocalInterface10 = strongBinder10.queryLocalInterface("com.google.android.gms.measurement.api.internal.IBundleReceiver");
                    k9 = iInterfaceQueryLocalInterface10 instanceof L ? (L) iInterfaceQueryLocalInterface10 : new K(strongBinder10);
                }
                AbstractC3081y.b(parcel);
                getGmpAppId(k9);
                break;
            case EventType.WINDOW_STATE /* 22 */:
                IBinder strongBinder11 = parcel.readStrongBinder();
                if (strongBinder11 != null) {
                    IInterface iInterfaceQueryLocalInterface11 = strongBinder11.queryLocalInterface("com.google.android.gms.measurement.api.internal.IBundleReceiver");
                    k8 = iInterfaceQueryLocalInterface11 instanceof L ? (L) iInterfaceQueryLocalInterface11 : new K(strongBinder11);
                }
                AbstractC3081y.b(parcel);
                generateEventId(k8);
                break;
            case EventType.AUDIO /* 23 */:
                String string17 = parcel.readString();
                long j12 = parcel.readLong();
                AbstractC3081y.b(parcel);
                beginAdUnitExposure(string17, j12);
                break;
            case EventType.VIDEO /* 24 */:
                String string18 = parcel.readString();
                long j13 = parcel.readLong();
                AbstractC3081y.b(parcel);
                endAdUnitExposure(string18, j13);
                break;
            case EventType.SUBS /* 25 */:
                com.google.android.gms.dynamic.a aVarV34 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                long j14 = parcel.readLong();
                AbstractC3081y.b(parcel);
                onActivityStarted(aVarV34, j14);
                break;
            case EventType.CDN /* 26 */:
                com.google.android.gms.dynamic.a aVarV35 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                long j15 = parcel.readLong();
                AbstractC3081y.b(parcel);
                onActivityStopped(aVarV35, j15);
                break;
            case 27:
                com.google.android.gms.dynamic.a aVarV36 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                Bundle bundle5 = (Bundle) AbstractC3081y.a(parcel, Bundle.CREATOR);
                long j16 = parcel.readLong();
                AbstractC3081y.b(parcel);
                onActivityCreated(aVarV36, bundle5, j16);
                break;
            case 28:
                com.google.android.gms.dynamic.a aVarV37 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                long j17 = parcel.readLong();
                AbstractC3081y.b(parcel);
                onActivityDestroyed(aVarV37, j17);
                break;
            case 29:
                com.google.android.gms.dynamic.a aVarV38 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                long j18 = parcel.readLong();
                AbstractC3081y.b(parcel);
                onActivityPaused(aVarV38, j18);
                break;
            case 30:
                com.google.android.gms.dynamic.a aVarV39 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                long j19 = parcel.readLong();
                AbstractC3081y.b(parcel);
                onActivityResumed(aVarV39, j19);
                break;
            case 31:
                com.google.android.gms.dynamic.a aVarV310 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                IBinder strongBinder12 = parcel.readStrongBinder();
                if (strongBinder12 != null) {
                    IInterface iInterfaceQueryLocalInterface12 = strongBinder12.queryLocalInterface("com.google.android.gms.measurement.api.internal.IBundleReceiver");
                    k7 = iInterfaceQueryLocalInterface12 instanceof L ? (L) iInterfaceQueryLocalInterface12 : new K(strongBinder12);
                }
                long j20 = parcel.readLong();
                AbstractC3081y.b(parcel);
                onActivitySaveInstanceState(aVarV310, k7, j20);
                break;
            case 32:
                Bundle bundle6 = (Bundle) AbstractC3081y.a(parcel, Bundle.CREATOR);
                IBinder strongBinder13 = parcel.readStrongBinder();
                if (strongBinder13 != null) {
                    IInterface iInterfaceQueryLocalInterface13 = strongBinder13.queryLocalInterface("com.google.android.gms.measurement.api.internal.IBundleReceiver");
                    k6 = iInterfaceQueryLocalInterface13 instanceof L ? (L) iInterfaceQueryLocalInterface13 : new K(strongBinder13);
                }
                long j21 = parcel.readLong();
                AbstractC3081y.b(parcel);
                performAction(bundle6, k6, j21);
                break;
            case 33:
                int i2 = parcel.readInt();
                String string19 = parcel.readString();
                com.google.android.gms.dynamic.a aVarV311 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                com.google.android.gms.dynamic.a aVarV312 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                com.google.android.gms.dynamic.a aVarV313 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC3081y.b(parcel);
                logHealthData(i2, string19, aVarV311, aVarV312, aVarV313);
                break;
            case 34:
                IBinder strongBinder14 = parcel.readStrongBinder();
                if (strongBinder14 != null) {
                    IInterface iInterfaceQueryLocalInterface14 = strongBinder14.queryLocalInterface("com.google.android.gms.measurement.api.internal.IEventHandlerProxy");
                    o3 = iInterfaceQueryLocalInterface14 instanceof P ? (P) iInterfaceQueryLocalInterface14 : new O(strongBinder14);
                }
                AbstractC3081y.b(parcel);
                setEventInterceptor(o3);
                break;
            case 35:
                IBinder strongBinder15 = parcel.readStrongBinder();
                if (strongBinder15 != null) {
                    IInterface iInterfaceQueryLocalInterface15 = strongBinder15.queryLocalInterface("com.google.android.gms.measurement.api.internal.IEventHandlerProxy");
                    o2 = iInterfaceQueryLocalInterface15 instanceof P ? (P) iInterfaceQueryLocalInterface15 : new O(strongBinder15);
                }
                AbstractC3081y.b(parcel);
                registerOnMeasurementEventListener(o2);
                break;
            case 36:
                IBinder strongBinder16 = parcel.readStrongBinder();
                if (strongBinder16 != null) {
                    IInterface iInterfaceQueryLocalInterface16 = strongBinder16.queryLocalInterface("com.google.android.gms.measurement.api.internal.IEventHandlerProxy");
                    o = iInterfaceQueryLocalInterface16 instanceof P ? (P) iInterfaceQueryLocalInterface16 : new O(strongBinder16);
                }
                AbstractC3081y.b(parcel);
                unregisterOnMeasurementEventListener(o);
                break;
            case 37:
                HashMap hashMap = parcel.readHashMap(AbstractC3081y.a);
                AbstractC3081y.b(parcel);
                initForTests(hashMap);
                break;
            case 38:
                IBinder strongBinder17 = parcel.readStrongBinder();
                if (strongBinder17 != null) {
                    IInterface iInterfaceQueryLocalInterface17 = strongBinder17.queryLocalInterface("com.google.android.gms.measurement.api.internal.IBundleReceiver");
                    k5 = iInterfaceQueryLocalInterface17 instanceof L ? (L) iInterfaceQueryLocalInterface17 : new K(strongBinder17);
                }
                int i3 = parcel.readInt();
                AbstractC3081y.b(parcel);
                getTestFlag(k5, i3);
                break;
            case 39:
                ClassLoader classLoader4 = AbstractC3081y.a;
                z = parcel.readInt() != 0;
                AbstractC3081y.b(parcel);
                setDataCollectionEnabled(z);
                break;
            case RequestError.NETWORK_FAILURE /* 40 */:
                IBinder strongBinder18 = parcel.readStrongBinder();
                if (strongBinder18 != null) {
                    IInterface iInterfaceQueryLocalInterface18 = strongBinder18.queryLocalInterface("com.google.android.gms.measurement.api.internal.IBundleReceiver");
                    k4 = iInterfaceQueryLocalInterface18 instanceof L ? (L) iInterfaceQueryLocalInterface18 : new K(strongBinder18);
                }
                AbstractC3081y.b(parcel);
                isDataCollectionEnabled(k4);
                break;
            case RequestError.NO_DEV_KEY /* 41 */:
            case 47:
            case 49:
            default:
                return false;
            case 42:
                Bundle bundle7 = (Bundle) AbstractC3081y.a(parcel, Bundle.CREATOR);
                AbstractC3081y.b(parcel);
                setDefaultEventParameters(bundle7);
                break;
            case 43:
                long j22 = parcel.readLong();
                AbstractC3081y.b(parcel);
                clearMeasurementEnabled(j22);
                break;
            case 44:
                Bundle bundle8 = (Bundle) AbstractC3081y.a(parcel, Bundle.CREATOR);
                long j23 = parcel.readLong();
                AbstractC3081y.b(parcel);
                setConsent(bundle8, j23);
                break;
            case 45:
                Bundle bundle9 = (Bundle) AbstractC3081y.a(parcel, Bundle.CREATOR);
                long j24 = parcel.readLong();
                AbstractC3081y.b(parcel);
                setConsentThirdParty(bundle9, j24);
                break;
            case 46:
                IBinder strongBinder19 = parcel.readStrongBinder();
                if (strongBinder19 != null) {
                    IInterface iInterfaceQueryLocalInterface19 = strongBinder19.queryLocalInterface("com.google.android.gms.measurement.api.internal.IBundleReceiver");
                    k3 = iInterfaceQueryLocalInterface19 instanceof L ? (L) iInterfaceQueryLocalInterface19 : new K(strongBinder19);
                }
                AbstractC3081y.b(parcel);
                getSessionId(k3);
                break;
            case 48:
                Intent intent = (Intent) AbstractC3081y.a(parcel, Intent.CREATOR);
                AbstractC3081y.b(parcel);
                setSgtmDebugInfo(intent);
                break;
            case RequestError.RESPONSE_CODE_FAILURE /* 50 */:
                zzdj zzdjVar = (zzdj) AbstractC3081y.a(parcel, zzdj.CREATOR);
                String string20 = parcel.readString();
                String string21 = parcel.readString();
                long j25 = parcel.readLong();
                AbstractC3081y.b(parcel);
                setCurrentScreenByScionActivityInfo(zzdjVar, string20, string21, j25);
                break;
            case 51:
                zzdj zzdjVar2 = (zzdj) AbstractC3081y.a(parcel, zzdj.CREATOR);
                long j26 = parcel.readLong();
                AbstractC3081y.b(parcel);
                onActivityStartedByScionActivityInfo(zzdjVar2, j26);
                break;
            case 52:
                zzdj zzdjVar3 = (zzdj) AbstractC3081y.a(parcel, zzdj.CREATOR);
                long j27 = parcel.readLong();
                AbstractC3081y.b(parcel);
                onActivityStoppedByScionActivityInfo(zzdjVar3, j27);
                break;
            case 53:
                zzdj zzdjVar4 = (zzdj) AbstractC3081y.a(parcel, zzdj.CREATOR);
                Bundle bundle10 = (Bundle) AbstractC3081y.a(parcel, Bundle.CREATOR);
                long j28 = parcel.readLong();
                AbstractC3081y.b(parcel);
                onActivityCreatedByScionActivityInfo(zzdjVar4, bundle10, j28);
                break;
            case 54:
                zzdj zzdjVar5 = (zzdj) AbstractC3081y.a(parcel, zzdj.CREATOR);
                long j29 = parcel.readLong();
                AbstractC3081y.b(parcel);
                onActivityDestroyedByScionActivityInfo(zzdjVar5, j29);
                break;
            case 55:
                zzdj zzdjVar6 = (zzdj) AbstractC3081y.a(parcel, zzdj.CREATOR);
                long j30 = parcel.readLong();
                AbstractC3081y.b(parcel);
                onActivityPausedByScionActivityInfo(zzdjVar6, j30);
                break;
            case 56:
                zzdj zzdjVar7 = (zzdj) AbstractC3081y.a(parcel, zzdj.CREATOR);
                long j31 = parcel.readLong();
                AbstractC3081y.b(parcel);
                onActivityResumedByScionActivityInfo(zzdjVar7, j31);
                break;
            case 57:
                zzdj zzdjVar8 = (zzdj) AbstractC3081y.a(parcel, zzdj.CREATOR);
                IBinder strongBinder20 = parcel.readStrongBinder();
                if (strongBinder20 != null) {
                    IInterface iInterfaceQueryLocalInterface20 = strongBinder20.queryLocalInterface("com.google.android.gms.measurement.api.internal.IBundleReceiver");
                    k2 = iInterfaceQueryLocalInterface20 instanceof L ? (L) iInterfaceQueryLocalInterface20 : new K(strongBinder20);
                }
                long j32 = parcel.readLong();
                AbstractC3081y.b(parcel);
                onActivitySaveInstanceStateByScionActivityInfo(zzdjVar8, k2, j32);
                break;
            case 58:
                IBinder strongBinder21 = parcel.readStrongBinder();
                if (strongBinder21 != null) {
                    IInterface iInterfaceQueryLocalInterface21 = strongBinder21.queryLocalInterface("com.google.android.gms.measurement.api.internal.IDynamiteUploadBatchesCallback");
                    m = iInterfaceQueryLocalInterface21 instanceof N ? (N) iInterfaceQueryLocalInterface21 : new M(strongBinder21, "com.google.android.gms.measurement.api.internal.IDynamiteUploadBatchesCallback", 4);
                }
                AbstractC3081y.b(parcel);
                retrieveAndUploadBatches(m);
                break;
        }
        parcel2.writeNoException();
        return true;
    }
}

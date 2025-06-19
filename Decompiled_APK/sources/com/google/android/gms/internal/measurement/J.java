package com.google.android.gms.internal.measurement;

import android.content.Intent;
import android.os.Bundle;
import android.os.IInterface;
import java.util.Map;

/* loaded from: classes2.dex */
public interface J extends IInterface {
    void beginAdUnitExposure(String str, long j);

    void clearConditionalUserProperty(String str, String str2, Bundle bundle);

    void clearMeasurementEnabled(long j);

    void endAdUnitExposure(String str, long j);

    void generateEventId(L l);

    void getAppInstanceId(L l);

    void getCachedAppInstanceId(L l);

    void getConditionalUserProperties(String str, String str2, L l);

    void getCurrentScreenClass(L l);

    void getCurrentScreenName(L l);

    void getGmpAppId(L l);

    void getMaxUserProperties(String str, L l);

    void getSessionId(L l);

    void getTestFlag(L l, int i);

    void getUserProperties(String str, String str2, boolean z, L l);

    void initForTests(Map map);

    void initialize(com.google.android.gms.dynamic.a aVar, zzdh zzdhVar, long j);

    void isDataCollectionEnabled(L l);

    void logEvent(String str, String str2, Bundle bundle, boolean z, boolean z2, long j);

    void logEventAndBundle(String str, String str2, Bundle bundle, L l, long j);

    void logHealthData(int i, String str, com.google.android.gms.dynamic.a aVar, com.google.android.gms.dynamic.a aVar2, com.google.android.gms.dynamic.a aVar3);

    void onActivityCreated(com.google.android.gms.dynamic.a aVar, Bundle bundle, long j);

    void onActivityCreatedByScionActivityInfo(zzdj zzdjVar, Bundle bundle, long j);

    void onActivityDestroyed(com.google.android.gms.dynamic.a aVar, long j);

    void onActivityDestroyedByScionActivityInfo(zzdj zzdjVar, long j);

    void onActivityPaused(com.google.android.gms.dynamic.a aVar, long j);

    void onActivityPausedByScionActivityInfo(zzdj zzdjVar, long j);

    void onActivityResumed(com.google.android.gms.dynamic.a aVar, long j);

    void onActivityResumedByScionActivityInfo(zzdj zzdjVar, long j);

    void onActivitySaveInstanceState(com.google.android.gms.dynamic.a aVar, L l, long j);

    void onActivitySaveInstanceStateByScionActivityInfo(zzdj zzdjVar, L l, long j);

    void onActivityStarted(com.google.android.gms.dynamic.a aVar, long j);

    void onActivityStartedByScionActivityInfo(zzdj zzdjVar, long j);

    void onActivityStopped(com.google.android.gms.dynamic.a aVar, long j);

    void onActivityStoppedByScionActivityInfo(zzdj zzdjVar, long j);

    void performAction(Bundle bundle, L l, long j);

    void registerOnMeasurementEventListener(P p);

    void resetAnalyticsData(long j);

    void retrieveAndUploadBatches(N n);

    void setConditionalUserProperty(Bundle bundle, long j);

    void setConsent(Bundle bundle, long j);

    void setConsentThirdParty(Bundle bundle, long j);

    void setCurrentScreen(com.google.android.gms.dynamic.a aVar, String str, String str2, long j);

    void setCurrentScreenByScionActivityInfo(zzdj zzdjVar, String str, String str2, long j);

    void setDataCollectionEnabled(boolean z);

    void setDefaultEventParameters(Bundle bundle);

    void setEventInterceptor(P p);

    void setInstanceIdProvider(S s);

    void setMeasurementEnabled(boolean z, long j);

    void setMinimumSessionDuration(long j);

    void setSessionTimeoutDuration(long j);

    void setSgtmDebugInfo(Intent intent);

    void setUserId(String str, long j);

    void setUserProperty(String str, String str2, com.google.android.gms.dynamic.a aVar, boolean z, long j);

    void unregisterOnMeasurementEventListener(P p);
}

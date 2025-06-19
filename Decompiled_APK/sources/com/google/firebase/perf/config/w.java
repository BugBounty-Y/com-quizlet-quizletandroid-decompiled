package com.google.firebase.perf.config;

/* loaded from: classes2.dex */
public final /* synthetic */ class w implements com.google.android.gms.tasks.d, com.google.android.gms.tasks.c {
    public final /* synthetic */ RemoteConfigManager a;

    public /* synthetic */ w(RemoteConfigManager remoteConfigManager) {
        this.a = remoteConfigManager;
    }

    @Override // com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        this.a.lambda$triggerFirebaseRemoteConfigFetchAndActivateOnSuccessfulFetch$0((Boolean) obj);
    }

    @Override // com.google.android.gms.tasks.c
    public void t(Exception exc) {
        this.a.lambda$triggerFirebaseRemoteConfigFetchAndActivateOnSuccessfulFetch$1(exc);
    }
}

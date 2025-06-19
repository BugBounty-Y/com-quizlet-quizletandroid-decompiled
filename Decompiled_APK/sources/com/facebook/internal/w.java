package com.facebook.internal;

import androidx.camera.camera2.internal.s0;

/* loaded from: classes.dex */
public final /* synthetic */ class w implements Runnable {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ com.facebook.appevents.l b;

    public /* synthetic */ w(com.facebook.appevents.l lVar) {
        this.b = lVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.getClass();
                break;
            default:
                this.b.getClass();
                C1563s.a(new s0(26), EnumC1562q.AAM);
                C1563s.a(new com.facebook.appevents.k(9), EnumC1562q.RestrictiveDataFiltering);
                C1563s.a(new com.facebook.appevents.k(10), EnumC1562q.PrivacyProtection);
                C1563s.a(new com.facebook.appevents.k(11), EnumC1562q.EventDeactivation);
                C1563s.a(new s0(27), EnumC1562q.BannedParamFiltering);
                C1563s.a(new s0(28), EnumC1562q.IapLogging);
                C1563s.a(new s0(29), EnumC1562q.StdParamEnforcement);
                C1563s.a(new com.facebook.appevents.k(0), EnumC1562q.ProtectedMode);
                C1563s.a(new com.facebook.appevents.k(1), EnumC1562q.MACARuleMatching);
                C1563s.a(new com.facebook.appevents.k(2), EnumC1562q.BlocklistEvents);
                C1563s.a(new com.facebook.appevents.k(3), EnumC1562q.FilterRedactedEvents);
                C1563s.a(new com.facebook.appevents.k(4), EnumC1562q.FilterSensitiveParams);
                C1563s.a(new com.facebook.appevents.k(5), EnumC1562q.CloudBridge);
                C1563s.a(new com.facebook.appevents.k(6), EnumC1562q.GPSARATriggers);
                C1563s.a(new com.facebook.appevents.k(7), EnumC1562q.GPSPACAProcessing);
                C1563s.a(new com.facebook.appevents.k(8), EnumC1562q.GPSTopicsObservation);
                break;
        }
    }

    public /* synthetic */ w(com.facebook.appevents.l lVar, v vVar) {
        this.b = lVar;
    }
}

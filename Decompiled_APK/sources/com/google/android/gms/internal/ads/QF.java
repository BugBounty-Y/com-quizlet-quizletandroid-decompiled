package com.google.android.gms.internal.ads;

import android.media.Spatializer;
import android.media.Spatializer$OnSpatializerStateChangedListener;

/* loaded from: classes2.dex */
public final class QF implements Spatializer$OnSpatializerStateChangedListener {
    public final /* synthetic */ VF a;

    public QF(VF vf) {
        this.a = vf;
    }

    public final void onSpatializerAvailableChanged(Spatializer spatializer, boolean z) {
        this.a.e();
    }

    public final void onSpatializerEnabledChanged(Spatializer spatializer, boolean z) {
        this.a.e();
    }
}

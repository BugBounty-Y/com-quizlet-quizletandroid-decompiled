package com.google.android.gms.internal.measurement;

import android.os.Bundle;

/* loaded from: classes2.dex */
public final class V extends AbstractRunnableC2988f0 {
    public final /* synthetic */ int e;
    public final /* synthetic */ C3008j0 f;
    public final /* synthetic */ Object g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ V(C3008j0 c3008j0, Object obj, int i) {
        super(c3008j0, true);
        this.e = i;
        this.g = obj;
        this.f = c3008j0;
    }

    @Override // com.google.android.gms.internal.measurement.AbstractRunnableC2988f0
    public final void a() {
        switch (this.e) {
            case 0:
                J j = this.f.i;
                com.google.android.gms.common.internal.u.h(j);
                j.setConditionalUserProperty((Bundle) this.g, this.a);
                break;
            case 1:
                J j2 = this.f.i;
                com.google.android.gms.common.internal.u.h(j2);
                j2.retrieveAndUploadBatches(new Y((com.google.android.gms.measurement.internal.A0) this.g));
                break;
            case 2:
                J j3 = this.f.i;
                com.google.android.gms.common.internal.u.h(j3);
                j3.logHealthData(5, "Error with data collection. Data lost.", new com.google.android.gms.dynamic.b((Exception) this.g), new com.google.android.gms.dynamic.b(null), new com.google.android.gms.dynamic.b(null));
                break;
            case 3:
                J j4 = this.f.i;
                com.google.android.gms.common.internal.u.h(j4);
                j4.setEventInterceptor((BinderC2993g0) this.g);
                break;
            default:
                J j5 = this.f.i;
                com.google.android.gms.common.internal.u.h(j5);
                j5.registerOnMeasurementEventListener((BinderC2993g0) this.g);
                break;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public V(C3008j0 c3008j0, Exception exc) {
        super(c3008j0, false);
        this.e = 2;
        this.g = exc;
        this.f = c3008j0;
    }
}

package com.google.android.gms.internal.measurement;

import android.app.Activity;
import android.os.Bundle;

/* renamed from: com.google.android.gms.internal.measurement.d0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2978d0 extends AbstractRunnableC2988f0 {
    public final /* synthetic */ int e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;
    public final /* synthetic */ Object h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C2978d0(C3008j0 c3008j0, Object obj, G g, int i) {
        super(c3008j0, true);
        this.e = i;
        this.h = obj;
        this.f = g;
        this.g = c3008j0;
    }

    @Override // com.google.android.gms.internal.measurement.AbstractRunnableC2988f0
    public final void a() {
        Bundle bundle;
        switch (this.e) {
            case 0:
                J j = ((C3008j0) this.g).i;
                com.google.android.gms.common.internal.u.h(j);
                j.performAction((Bundle) this.h, (G) this.f, this.a);
                break;
            case 1:
                J j2 = ((C3008j0) this.g).i;
                com.google.android.gms.common.internal.u.h(j2);
                j2.getMaxUserProperties((String) this.h, (G) this.f);
                break;
            case 2:
                Bundle bundle2 = (Bundle) this.h;
                if (bundle2 != null) {
                    bundle = new Bundle();
                    if (bundle2.containsKey("com.google.app_measurement.screen_service")) {
                        Object obj = bundle2.get("com.google.app_measurement.screen_service");
                        if (obj instanceof Bundle) {
                            bundle.putBundle("com.google.app_measurement.screen_service", (Bundle) obj);
                        }
                    }
                } else {
                    bundle = null;
                }
                J j3 = ((C3003i0) this.g).a.i;
                com.google.android.gms.common.internal.u.h(j3);
                Activity activity = (Activity) this.f;
                j3.onActivityCreatedByScionActivityInfo(zzdj.a(activity), bundle, this.b);
                break;
            default:
                J j4 = ((C3003i0) this.g).a.i;
                com.google.android.gms.common.internal.u.h(j4);
                j4.onActivitySaveInstanceStateByScionActivityInfo(zzdj.a((Activity) this.h), (G) this.f, this.b);
                break;
        }
    }

    @Override // com.google.android.gms.internal.measurement.AbstractRunnableC2988f0
    public void b() {
        switch (this.e) {
            case 0:
                ((G) this.f).t1(null);
                break;
            case 1:
                ((G) this.f).t1(null);
                break;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C2978d0(C3003i0 c3003i0, Activity activity, G g) {
        super(c3003i0.a, true);
        this.e = 3;
        this.h = activity;
        this.f = g;
        this.g = c3003i0;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C2978d0(C3003i0 c3003i0, Bundle bundle, Activity activity) {
        super(c3003i0.a, true);
        this.e = 2;
        this.h = bundle;
        this.f = activity;
        this.g = c3003i0;
    }
}

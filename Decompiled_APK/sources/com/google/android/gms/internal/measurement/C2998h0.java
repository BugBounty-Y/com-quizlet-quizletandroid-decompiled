package com.google.android.gms.internal.measurement;

import android.app.Activity;

/* renamed from: com.google.android.gms.internal.measurement.h0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2998h0 extends AbstractRunnableC2988f0 {
    public final /* synthetic */ int e;
    public final /* synthetic */ Activity f;
    public final /* synthetic */ C3003i0 g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C2998h0(C3003i0 c3003i0, Activity activity, int i) {
        super(c3003i0.a, true);
        this.e = i;
        switch (i) {
            case 1:
                this.f = activity;
                this.g = c3003i0;
                super(c3003i0.a, true);
                break;
            case 2:
                this.f = activity;
                this.g = c3003i0;
                super(c3003i0.a, true);
                break;
            case 3:
                this.f = activity;
                this.g = c3003i0;
                super(c3003i0.a, true);
                break;
            case 4:
                this.f = activity;
                this.g = c3003i0;
                super(c3003i0.a, true);
                break;
            default:
                this.f = activity;
                this.g = c3003i0;
                break;
        }
    }

    @Override // com.google.android.gms.internal.measurement.AbstractRunnableC2988f0
    public final void a() {
        switch (this.e) {
            case 0:
                J j = this.g.a.i;
                com.google.android.gms.common.internal.u.h(j);
                j.onActivityStartedByScionActivityInfo(zzdj.a(this.f), this.b);
                break;
            case 1:
                J j2 = this.g.a.i;
                com.google.android.gms.common.internal.u.h(j2);
                j2.onActivityResumedByScionActivityInfo(zzdj.a(this.f), this.b);
                break;
            case 2:
                J j3 = this.g.a.i;
                com.google.android.gms.common.internal.u.h(j3);
                j3.onActivityPausedByScionActivityInfo(zzdj.a(this.f), this.b);
                break;
            case 3:
                J j4 = this.g.a.i;
                com.google.android.gms.common.internal.u.h(j4);
                j4.onActivityStoppedByScionActivityInfo(zzdj.a(this.f), this.b);
                break;
            default:
                J j5 = this.g.a.i;
                com.google.android.gms.common.internal.u.h(j5);
                j5.onActivityDestroyedByScionActivityInfo(zzdj.a(this.f), this.b);
                break;
        }
    }
}

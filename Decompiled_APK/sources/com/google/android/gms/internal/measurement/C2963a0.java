package com.google.android.gms.internal.measurement;

/* renamed from: com.google.android.gms.internal.measurement.a0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2963a0 extends AbstractRunnableC2988f0 {
    public final /* synthetic */ int e;
    public final /* synthetic */ G f;
    public final /* synthetic */ C3008j0 g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C2963a0(C3008j0 c3008j0, G g, int i) {
        super(c3008j0, true);
        this.e = i;
        this.f = g;
        this.g = c3008j0;
    }

    @Override // com.google.android.gms.internal.measurement.AbstractRunnableC2988f0
    public final void a() {
        switch (this.e) {
            case 0:
                J j = this.g.i;
                com.google.android.gms.common.internal.u.h(j);
                j.getGmpAppId(this.f);
                break;
            case 1:
                J j2 = this.g.i;
                com.google.android.gms.common.internal.u.h(j2);
                j2.getCachedAppInstanceId(this.f);
                break;
            case 2:
                J j3 = this.g.i;
                com.google.android.gms.common.internal.u.h(j3);
                j3.generateEventId(this.f);
                break;
            case 3:
                J j4 = this.g.i;
                com.google.android.gms.common.internal.u.h(j4);
                j4.getCurrentScreenName(this.f);
                break;
            default:
                J j5 = this.g.i;
                com.google.android.gms.common.internal.u.h(j5);
                j5.getCurrentScreenClass(this.f);
                break;
        }
    }

    @Override // com.google.android.gms.internal.measurement.AbstractRunnableC2988f0
    public final void b() {
        switch (this.e) {
            case 0:
                this.f.t1(null);
                break;
            case 1:
                this.f.t1(null);
                break;
            case 2:
                this.f.t1(null);
                break;
            case 3:
                this.f.t1(null);
                break;
            default:
                this.f.t1(null);
                break;
        }
    }
}

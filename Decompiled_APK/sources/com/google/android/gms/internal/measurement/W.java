package com.google.android.gms.internal.measurement;

/* loaded from: classes2.dex */
public final class W extends AbstractRunnableC2988f0 {
    public final /* synthetic */ int e;
    public final /* synthetic */ String f;
    public final /* synthetic */ C3008j0 g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ W(C3008j0 c3008j0, String str, int i) {
        super(c3008j0, true);
        this.e = i;
        this.f = str;
        this.g = c3008j0;
    }

    @Override // com.google.android.gms.internal.measurement.AbstractRunnableC2988f0
    public final void a() {
        switch (this.e) {
            case 0:
                J j = this.g.i;
                com.google.android.gms.common.internal.u.h(j);
                j.setUserId(this.f, this.a);
                break;
            case 1:
                J j2 = this.g.i;
                com.google.android.gms.common.internal.u.h(j2);
                j2.beginAdUnitExposure(this.f, this.b);
                break;
            default:
                J j3 = this.g.i;
                com.google.android.gms.common.internal.u.h(j3);
                j3.endAdUnitExposure(this.f, this.b);
                break;
        }
    }
}

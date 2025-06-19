package com.google.android.gms.measurement.internal;

/* loaded from: classes2.dex */
public final class V0 extends AbstractC3876k {
    public final /* synthetic */ int e;
    public final /* synthetic */ Y0 f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ V0(Y0 y0, Y y, int i) {
        super(y);
        this.e = i;
        this.f = y0;
    }

    @Override // com.google.android.gms.measurement.internal.AbstractC3876k
    public final void b() {
        switch (this.e) {
            case 0:
                Y0 y0 = this.f;
                y0.S();
                if (y0.b0()) {
                    I i = ((Y) y0.b).i;
                    Y.k(i);
                    i.o.f("Inactivity, disconnecting from the service");
                    y0.W();
                    break;
                }
                break;
            default:
                I i2 = ((Y) this.f.b).i;
                Y.k(i2);
                i2.j.f("Tasks have been queued for a long time");
                break;
        }
    }
}

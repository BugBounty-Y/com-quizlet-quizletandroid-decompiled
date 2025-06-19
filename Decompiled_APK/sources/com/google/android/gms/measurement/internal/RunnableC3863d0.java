package com.google.android.gms.measurement.internal;

/* renamed from: com.google.android.gms.measurement.internal.d0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class RunnableC3863d0 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.google.android.gms.internal.measurement.L b;
    public final /* synthetic */ AppMeasurementDynamiteService c;

    public /* synthetic */ RunnableC3863d0(AppMeasurementDynamiteService appMeasurementDynamiteService, com.google.android.gms.internal.measurement.L l, int i) {
        this.a = i;
        this.b = l;
        this.c = appMeasurementDynamiteService;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                Y0 y0E = Z.e(this.c.a);
                y0E.i0(new androidx.core.provider.k(19, y0E, y0E.f0(false), this.b, false));
                break;
            default:
                AppMeasurementDynamiteService appMeasurementDynamiteService = this.c;
                x1 x1Var = appMeasurementDynamiteService.a.l;
                Y.h(x1Var);
                Y y = appMeasurementDynamiteService.a;
                x1Var.n0(this.b, y.B != null && y.B.booleanValue());
                break;
        }
    }
}

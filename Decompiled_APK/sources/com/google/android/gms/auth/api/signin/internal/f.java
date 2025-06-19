package com.google.android.gms.auth.api.signin.internal;

import android.os.Parcel;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.internal.BasePendingResult;
import com.google.android.gms.common.api.internal.p;
import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class f extends BasePendingResult {
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(p pVar, int i) {
        super(pVar);
        this.a = i;
        u.i(pVar, "GoogleApiClient must not be null");
        u.i(com.google.android.gms.auth.api.a.a, "Api must not be null");
    }

    @Override // com.google.android.gms.common.api.internal.BasePendingResult
    public final /* bridge */ /* synthetic */ com.google.android.gms.common.api.k c(Status status) {
        int i = this.a;
        return status;
    }

    public final void e(com.google.android.gms.common.api.c cVar) {
        switch (this.a) {
            case 0:
                d dVar = (d) cVar;
                j jVar = (j) dVar.m();
                e eVar = new e(this, 0);
                Parcel parcelX = jVar.X();
                int i = com.google.android.gms.internal.p000authapi.h.a;
                parcelX.writeStrongBinder(eVar);
                com.google.android.gms.internal.p000authapi.h.c(parcelX, dVar.A);
                jVar.f0(102, parcelX);
                break;
            default:
                d dVar2 = (d) cVar;
                j jVar2 = (j) dVar2.m();
                e eVar2 = new e(this, 1);
                Parcel parcelX2 = jVar2.X();
                int i2 = com.google.android.gms.internal.p000authapi.h.a;
                parcelX2.writeStrongBinder(eVar2);
                com.google.android.gms.internal.p000authapi.h.c(parcelX2, dVar2.A);
                jVar2.f0(103, parcelX2);
                break;
        }
    }

    public final void f(Status status) {
        u.a("Failed result must not be success", !status.a());
        setResult(c(status));
    }
}

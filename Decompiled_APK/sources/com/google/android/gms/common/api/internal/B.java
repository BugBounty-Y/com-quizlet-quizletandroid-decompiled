package com.google.android.gms.common.api.internal;

import android.os.DeadObjectException;
import android.os.RemoteException;
import com.google.android.gms.common.Feature;
import com.google.android.gms.common.api.ApiException;
import com.google.android.gms.common.api.Status;

/* loaded from: classes2.dex */
public final class B extends t {
    public final com.google.android.gms.tasks.f b;

    public B(AbstractC1650h abstractC1650h, com.google.android.gms.tasks.f fVar) {
        super(4);
        this.b = fVar;
    }

    @Override // com.google.android.gms.common.api.internal.C
    public final void a(Status status) {
        this.b.c(new ApiException(status));
    }

    @Override // com.google.android.gms.common.api.internal.C
    public final void b(RuntimeException runtimeException) {
        this.b.c(runtimeException);
    }

    @Override // com.google.android.gms.common.api.internal.C
    public final /* bridge */ /* synthetic */ void c(com.quizlet.data.repository.explanations.myexplanations.a aVar, boolean z) {
    }

    @Override // com.google.android.gms.common.api.internal.C
    public final void d(n nVar) throws DeadObjectException {
        try {
            h(nVar);
        } catch (DeadObjectException e) {
            a(C.e(e));
            throw e;
        } catch (RemoteException e2) {
            a(C.e(e2));
        } catch (RuntimeException e3) {
            this.b.c(e3);
        }
    }

    @Override // com.google.android.gms.common.api.internal.t
    public final Feature[] f(n nVar) {
        return null;
    }

    @Override // com.google.android.gms.common.api.internal.t
    public final boolean g(n nVar) {
        return false;
    }

    public final void h(n nVar) {
        this.b.d(Boolean.FALSE);
    }
}

package com.google.android.gms.common.api.internal;

import android.os.DeadObjectException;
import android.os.RemoteException;
import com.google.android.gms.common.Feature;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.internal.ads.AbstractC2027eu;
import java.util.Map;

/* loaded from: classes2.dex */
public final class A extends t {
    public final AbstractC2027eu b;
    public final com.google.android.gms.tasks.f c;
    public final com.google.mlkit.common.sdkinternal.model.a d;

    public A(int i, AbstractC2027eu abstractC2027eu, com.google.android.gms.tasks.f fVar, com.google.mlkit.common.sdkinternal.model.a aVar) {
        super(i);
        this.c = fVar;
        this.b = abstractC2027eu;
        this.d = aVar;
        if (i == 2 && abstractC2027eu.d) {
            throw new IllegalArgumentException("Best-effort write calls cannot pass methods that should auto-resolve missing features.");
        }
    }

    @Override // com.google.android.gms.common.api.internal.C
    public final void a(Status status) {
        this.d.getClass();
        this.c.c(com.google.android.gms.common.internal.u.m(status));
    }

    @Override // com.google.android.gms.common.api.internal.C
    public final void b(RuntimeException runtimeException) {
        this.c.c(runtimeException);
    }

    @Override // com.google.android.gms.common.api.internal.C
    public final void c(com.quizlet.data.repository.explanations.myexplanations.a aVar, boolean z) {
        Boolean boolValueOf = Boolean.valueOf(z);
        Map map = (Map) aVar.c;
        com.google.android.gms.tasks.f fVar = this.c;
        map.put(fVar, boolValueOf);
        fVar.a.addOnCompleteListener(new com.quizlet.data.repository.searchexplanations.c(aVar, fVar));
    }

    @Override // com.google.android.gms.common.api.internal.C
    public final void d(n nVar) throws DeadObjectException {
        com.google.android.gms.tasks.f fVar = this.c;
        try {
            this.b.b(nVar.b, fVar);
        } catch (DeadObjectException e) {
            throw e;
        } catch (RemoteException e2) {
            a(C.e(e2));
        } catch (RuntimeException e3) {
            fVar.c(e3);
        }
    }

    @Override // com.google.android.gms.common.api.internal.t
    public final Feature[] f(n nVar) {
        return (Feature[]) this.b.b;
    }

    @Override // com.google.android.gms.common.api.internal.t
    public final boolean g(n nVar) {
        return this.b.d;
    }
}

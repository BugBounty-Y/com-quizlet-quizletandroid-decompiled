package com.google.android.gms.common.api.internal;

import android.os.DeadObjectException;
import android.os.RemoteException;
import android.util.Log;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.common.api.Status;
import java.util.Map;

/* loaded from: classes2.dex */
public final class z extends C {
    public final com.google.android.gms.auth.api.signin.internal.f b;

    public z(com.google.android.gms.auth.api.signin.internal.f fVar) {
        super(1);
        this.b = fVar;
    }

    @Override // com.google.android.gms.common.api.internal.C
    public final void a(Status status) {
        try {
            this.b.f(status);
        } catch (IllegalStateException e) {
            Log.w("ApiCallRunner", "Exception reporting failure", e);
        }
    }

    @Override // com.google.android.gms.common.api.internal.C
    public final void b(RuntimeException runtimeException) {
        String simpleName = runtimeException.getClass().getSimpleName();
        String localizedMessage = runtimeException.getLocalizedMessage();
        try {
            this.b.f(new Status(10, AbstractC0147y.g(new StringBuilder(simpleName.length() + 2 + String.valueOf(localizedMessage).length()), simpleName, ": ", localizedMessage), null, null));
        } catch (IllegalStateException e) {
            Log.w("ApiCallRunner", "Exception reporting failure", e);
        }
    }

    @Override // com.google.android.gms.common.api.internal.C
    public final void c(com.quizlet.data.repository.explanations.myexplanations.a aVar, boolean z) {
        Boolean boolValueOf = Boolean.valueOf(z);
        Map map = (Map) aVar.b;
        com.google.android.gms.auth.api.signin.internal.f fVar = this.b;
        map.put(fVar, boolValueOf);
        fVar.addStatusListener(new F(aVar, fVar));
    }

    @Override // com.google.android.gms.common.api.internal.C
    public final void d(n nVar) throws DeadObjectException {
        try {
            com.google.android.gms.auth.api.signin.internal.f fVar = this.b;
            com.google.android.gms.common.api.c cVar = nVar.b;
            fVar.getClass();
            try {
                fVar.e(cVar);
            } catch (DeadObjectException e) {
                fVar.f(new Status(8, e.getLocalizedMessage(), null, null));
                throw e;
            } catch (RemoteException e2) {
                fVar.f(new Status(8, e2.getLocalizedMessage(), null, null));
            }
        } catch (RuntimeException e3) {
            b(e3);
        }
    }
}

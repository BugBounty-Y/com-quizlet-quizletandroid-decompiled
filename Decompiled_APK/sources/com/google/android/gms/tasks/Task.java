package com.google.android.gms.tasks;

import androidx.annotation.NonNull;
import java.util.concurrent.Executor;

/* loaded from: classes2.dex */
public abstract class Task<TResult> {
    public void a(Executor executor, b bVar) {
        throw new UnsupportedOperationException("addOnCanceledListener is not implemented");
    }

    @NonNull
    public Task<TResult> addOnCompleteListener(@NonNull OnCompleteListener<TResult> onCompleteListener) {
        throw new UnsupportedOperationException("addOnCompleteListener is not implemented");
    }

    public void b(Executor executor, OnCompleteListener onCompleteListener) {
        throw new UnsupportedOperationException("addOnCompleteListener is not implemented");
    }

    public abstract m c(Executor executor, c cVar);

    public abstract m d(Executor executor, d dVar);

    public Task e(Executor executor, a aVar) {
        throw new UnsupportedOperationException("continueWith is not implemented");
    }

    public Task f(Executor executor, a aVar) {
        throw new UnsupportedOperationException("continueWithTask is not implemented");
    }

    public abstract Exception g();

    public abstract Object h();

    public abstract Object i();

    public abstract boolean j();

    public abstract boolean k();

    public abstract boolean l();

    public Task m(e eVar) {
        throw new UnsupportedOperationException("onSuccessTask is not implemented");
    }

    public Task n(Executor executor, e eVar) {
        throw new UnsupportedOperationException("onSuccessTask is not implemented");
    }
}

package io.reactivex.rxjava3.android;

import android.os.Looper;
import com.google.firebase.crashlytics.internal.metadata.q;
import io.reactivex.rxjava3.disposables.b;
import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes3.dex */
public abstract class a implements b {
    public final AtomicBoolean a = new AtomicBoolean();

    public abstract void a();

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        if (this.a.compareAndSet(false, true)) {
            if (Looper.myLooper() == Looper.getMainLooper()) {
                a();
            } else {
                io.reactivex.rxjava3.android.schedulers.b.a().b(new q(this, 24));
            }
        }
    }
}

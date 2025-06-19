package androidx.lifecycle;

import android.app.Service;
import android.content.Intent;
import android.os.Handler;
import android.os.IBinder;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class M extends Service implements J {
    public final com.quizlet.data.repository.login.a a;

    public M() {
        Intrinsics.checkNotNullParameter(this, "provider");
        com.quizlet.data.repository.login.a aVar = new com.quizlet.data.repository.login.a();
        aVar.a = new L(this);
        aVar.b = new Handler();
        this.a = aVar;
    }

    @Override // androidx.lifecycle.J
    public final C getLifecycle() {
        return (L) this.a.a;
    }

    @Override // android.app.Service
    public final IBinder onBind(Intent intent) {
        Intrinsics.checkNotNullParameter(intent, "intent");
        com.quizlet.data.repository.login.a aVar = this.a;
        aVar.getClass();
        aVar.l(A.ON_START);
        return null;
    }

    @Override // android.app.Service
    public void onCreate() {
        com.quizlet.data.repository.login.a aVar = this.a;
        aVar.getClass();
        aVar.l(A.ON_CREATE);
        super.onCreate();
    }

    @Override // android.app.Service
    public void onDestroy() {
        com.quizlet.data.repository.login.a aVar = this.a;
        aVar.getClass();
        aVar.l(A.ON_STOP);
        aVar.l(A.ON_DESTROY);
        super.onDestroy();
    }

    @Override // android.app.Service
    public final void onStart(Intent intent, int i) {
        com.quizlet.data.repository.login.a aVar = this.a;
        aVar.getClass();
        aVar.l(A.ON_START);
        super.onStart(intent, i);
    }
}

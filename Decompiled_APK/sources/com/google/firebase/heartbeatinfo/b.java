package com.google.firebase.heartbeatinfo;

import android.content.Context;
import androidx.camera.camera2.internal.c0;
import com.google.firebase.components.q;
import com.google.firebase.messaging.FirebaseMessagingRegistrar;
import com.google.firebase.perf.FirebasePerfRegistrar;
import com.google.firebase.remoteconfig.RemoteConfigRegistrar;
import java.util.concurrent.Executor;

/* loaded from: classes2.dex */
public final /* synthetic */ class b implements com.google.firebase.components.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ q b;

    public /* synthetic */ b(q qVar, int i) {
        this.a = i;
        this.b = qVar;
    }

    @Override // com.google.firebase.components.d
    public final Object f(c0 c0Var) {
        switch (this.a) {
            case 0:
                return new d((Context) c0Var.get(Context.class), ((com.google.firebase.h) c0Var.get(com.google.firebase.h.class)).d(), c0Var.c(q.a(e.class)), c0Var.b(com.google.firebase.platforminfo.b.class), (Executor) c0Var.f(this.b));
            case 1:
                return FirebaseMessagingRegistrar.lambda$getComponents$0(this.b, c0Var);
            case 2:
                return FirebasePerfRegistrar.lambda$getComponents$0(this.b, c0Var);
            default:
                return RemoteConfigRegistrar.lambda$getComponents$0(this.b, c0Var);
        }
    }
}

package com.google.firebase.perf.injection.modules;

import com.google.android.gms.internal.mlkit_vision_barcode.S6;
import com.google.firebase.perf.config.RemoteConfigManager;
import com.google.firebase.perf.session.SessionManager;
import com.quizlet.local.cache.g;
import dagger.internal.c;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a implements c {
    public final /* synthetic */ int a;

    public /* synthetic */ a() {
        this.a = 3;
    }

    @Override // javax.inject.a
    public final Object get() {
        switch (this.a) {
            case 0:
                com.google.firebase.perf.config.a aVarE = com.google.firebase.perf.config.a.e();
                S6.c(aVarE);
                return aVarE;
            case 1:
                RemoteConfigManager remoteConfigManager = RemoteConfigManager.getInstance();
                S6.c(remoteConfigManager);
                return remoteConfigManager;
            case 2:
                SessionManager sessionManager = SessionManager.getInstance();
                S6.c(sessionManager);
                return sessionManager;
            default:
                com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
                Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
                return new g(60L);
        }
    }

    public /* synthetic */ a(com.quizlet.data.repository.explanations.exercise.b bVar, int i) {
        this.a = i;
    }
}

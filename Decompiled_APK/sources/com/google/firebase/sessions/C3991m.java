package com.google.firebase.sessions;

import android.content.Context;
import androidx.datastore.core.InterfaceC1076h;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.firebase.sessions.m, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3991m implements com.google.firebase.sessions.dagger.internal.b {
    public final /* synthetic */ int a;
    public final javax.inject.a b;

    public /* synthetic */ C3991m(javax.inject.a aVar, int i) {
        this.a = i;
        this.b = aVar;
    }

    @Override // javax.inject.a
    public final Object get() {
        javax.inject.a aVar = this.b;
        switch (this.a) {
            case 0:
                return new C3990l((com.google.firebase.inject.b) ((com.google.firebase.sessions.dagger.internal.c) aVar).a);
            case 1:
                com.google.firebase.h firebaseApp = (com.google.firebase.h) ((com.google.firebase.sessions.dagger.internal.c) aVar).a;
                Intrinsics.checkNotNullParameter(firebaseApp, "firebaseApp");
                P p = P.a;
                return P.a(firebaseApp);
            case 2:
                Context appContext = (Context) ((com.google.firebase.sessions.dagger.internal.c) aVar).a;
                Intrinsics.checkNotNullParameter(appContext, "appContext");
                return androidx.datastore.preferences.core.e.e(new com.airbnb.lottie.network.c(C3995q.b), new r(appContext, 0), 6);
            case 3:
                Context appContext2 = (Context) ((com.google.firebase.sessions.dagger.internal.c) aVar).a;
                Intrinsics.checkNotNullParameter(appContext2, "appContext");
                return androidx.datastore.preferences.core.e.e(new com.airbnb.lottie.network.c(C3995q.c), new r(appContext2, 1), 6);
            case 4:
                return new d0((Context) ((com.google.firebase.sessions.dagger.internal.c) aVar).a);
            case 5:
                return new com.google.firebase.sessions.settings.a((Context) ((com.google.firebase.sessions.dagger.internal.c) aVar).a);
            default:
                return new com.google.firebase.sessions.settings.n((InterfaceC1076h) aVar.get());
        }
    }
}

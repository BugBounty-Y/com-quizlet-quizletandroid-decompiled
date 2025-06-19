package com.quizlet.quizletandroid.interactor;

import com.google.android.gms.internal.mlkit_vision_camera.K1;
import io.reactivex.rxjava3.internal.operators.observable.C4887f;
import io.reactivex.rxjava3.internal.operators.observable.J;
import io.reactivex.rxjava3.internal.operators.observable.N;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes3.dex */
public final class t {
    public final com.quizlet.infra.legacysyncengine.managers.d a;
    public final retrofit2.adapter.rxjava3.d b;
    public final com.quizlet.infra.legacysyncengine.net.f c;
    public final com.quizlet.braze.e d;
    public final AbstractC5040y e;

    public t(com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager, retrofit2.adapter.rxjava3.d mapper, com.quizlet.infra.legacysyncengine.net.f syncDispatcher, com.quizlet.braze.e brazeUserManager, AbstractC5040y dispatcher) {
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        Intrinsics.checkNotNullParameter(syncDispatcher, "syncDispatcher");
        Intrinsics.checkNotNullParameter(brazeUserManager, "brazeUserManager");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.a = loggedInUserManager;
        this.b = mapper;
        this.c = syncDispatcher;
        this.d = brazeUserManager;
        this.e = dispatcher;
    }

    public final InterfaceC4992i a(boolean z) {
        com.quizlet.infra.legacysyncengine.managers.d dVar = this.a;
        if (z) {
            dVar.c();
        }
        io.reactivex.rxjava3.subjects.d dVar2 = dVar.l;
        dVar2.getClass();
        J jQ = new N(new C4887f(dVar2, 1), s.b, false).q(new s(this.b));
        Intrinsics.checkNotNullExpressionValue(jQ, "map(...)");
        return e0.s(K1.f(jQ), this.e);
    }
}

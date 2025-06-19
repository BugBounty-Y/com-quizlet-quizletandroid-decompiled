package com.quizlet.quizletandroid;

import com.quizlet.api.IQuizletApiClient;
import com.quizlet.eventlogger.EventLogger;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.i, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4626i implements dagger.internal.c {
    public final u a;
    public final int b;

    public C4626i(u uVar, int i) {
        this.a = uVar;
        this.b = i;
    }

    @Override // javax.inject.a
    public final Object get() {
        u uVar = this.a;
        int i = this.b;
        if (i != 0) {
            if (i == 1) {
                return new com.quizlet.quizletandroid.ui.usersettings.d(uVar.q(), com.quizlet.featuregate.injection.a.l(), com.quizlet.featuregate.injection.a.j(), (IQuizletApiClient) uVar.O.get(), uVar.s1(), (com.quizlet.infra.legacysyncengine.tasks.parse.f) uVar.F.get(), uVar.l0(), (com.quizlet.db.token.a) uVar.u.get(), (com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get());
            }
            throw new AssertionError(i);
        }
        com.quizlet.quizletandroid.injection.modules.a aVar = uVar.h;
        EventLogger eventLogger = (EventLogger) uVar.l0.get();
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        return new com.quizlet.quizletandroid.ui.setcreation.tracking.c(eventLogger);
    }
}

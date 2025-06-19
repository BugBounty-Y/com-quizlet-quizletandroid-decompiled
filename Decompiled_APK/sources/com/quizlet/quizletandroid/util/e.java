package com.quizlet.quizletandroid.util;

import io.reactivex.rxjava3.internal.operators.observable.C4887f;
import java.util.HashSet;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e {
    public final com.quizlet.infra.legacysyncengine.net.c a;
    public final com.quizlet.infra.legacysyncengine.managers.d b;
    public final HashSet c;
    public com.quizlet.infra.legacysyncengine.orm.query.a d;
    public final HashSet e;
    public final com.quizlet.infra.legacysyncengine.datasources.f f;

    public e(com.quizlet.infra.legacysyncengine.net.c loader, com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager) {
        Intrinsics.checkNotNullParameter(loader, "loader");
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        this.a = loader;
        this.b = loggedInUserManager;
        this.c = new HashSet();
        this.e = new HashSet();
        this.f = new com.quizlet.infra.legacysyncengine.datasources.f(this, 10);
        io.reactivex.rxjava3.subjects.d dVar = loggedInUserManager.l;
        dVar.getClass();
        new C4887f(dVar, 1).u(new c(this, 0), new com.quizlet.billing.manager.d(timber.log.c.a, 18), io.reactivex.rxjava3.internal.functions.d.c);
    }
}

package com.quizlet.infra.legacysyncengine.managers;

import com.braze.C1510p;
import com.google.firebase.perf.metrics.Trace;
import com.quizlet.api.IQuizletApiClient;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import com.quizlet.db.data.models.wrappers.LoggedInUserStatus;
import com.quizlet.db.data.net.tasks.ExecutionRouter;
import com.quizlet.eventlogger.events.CurrentUserEvent;
import com.quizlet.eventlogger.events.UserLogoutEvent;
import io.reactivex.rxjava3.core.o;
import io.reactivex.rxjava3.internal.operators.observable.C4887f;
import io.reactivex.rxjava3.internal.operators.observable.o0;
import io.reactivex.rxjava3.subjects.r;
import java.util.Locale;
import java.util.Objects;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d {
    public final com.squareup.otto.c a;
    public final DatabaseHelper b;
    public final ExecutionRouter c;
    public final com.quizlet.features.setpage.upsell.a d;
    public final UserInfoCache e;
    public final com.quizlet.db.token.a f;
    public final com.quizlet.infra.legacysyncengine.net.f g;
    public final IQuizletApiClient h;
    public final o i;
    public final o j;
    public final com.quizlet.infra.legacysyncengine.net.c k;
    public final io.reactivex.rxjava3.subjects.d l;
    public final com.quizlet.data.repository.widget.b m;
    public final g n;
    public final com.quizlet.data.interactor.school.b o;
    public final retrofit2.adapter.rxjava3.d p;
    public long q;
    public DBUser r;
    public com.quizlet.features.infra.studysetting.datasource.a s;
    public io.reactivex.rxjava3.internal.observers.h t;
    public r u;

    public d(DatabaseHelper databaseHelper, ExecutionRouter executionRouter, com.quizlet.features.setpage.upsell.a aVar, UserInfoCache userInfoCache, com.quizlet.db.token.a aVar2, com.quizlet.infra.legacysyncengine.net.c cVar, com.quizlet.infra.legacysyncengine.net.f fVar, IQuizletApiClient iQuizletApiClient, o oVar, o oVar2, com.squareup.otto.c cVar2, com.quizlet.data.repository.widget.b bVar, g gVar, com.quizlet.data.interactor.school.b bVar2, retrofit2.adapter.rxjava3.d dVar) throws IllegalAccessException, SecurityException, IllegalArgumentException {
        Trace traceA = com.google.firebase.perf.b.a("LoggedInUserManager_constructor_trace");
        this.l = io.reactivex.rxjava3.subjects.d.z();
        this.u = new r();
        this.b = databaseHelper;
        this.c = executionRouter;
        this.d = aVar;
        this.e = userInfoCache;
        this.f = aVar2;
        this.k = cVar;
        this.g = fVar;
        this.h = iQuizletApiClient;
        this.i = oVar;
        this.j = oVar2;
        this.a = cVar2;
        this.m = bVar;
        this.n = gVar;
        this.o = bVar2;
        this.p = dVar;
        Trace traceA2 = com.google.firebase.perf.b.a("LoggedInUserManager_loadInitialUser_trace");
        long personId = userInfoCache.getPersonId();
        this.q = personId;
        if (personId != 0) {
            b(personId);
        } else {
            d(null);
        }
        traceA2.stop();
        cVar2.d(this);
        traceA.stop();
    }

    public final io.reactivex.rxjava3.internal.operators.flowable.b a() {
        io.reactivex.rxjava3.subjects.d dVar = this.l;
        dVar.getClass();
        return new io.reactivex.rxjava3.internal.operators.flowable.b(new C4887f(dVar, 5), 2);
    }

    public final io.reactivex.rxjava3.subjects.f b(final long j) {
        final io.reactivex.rxjava3.subjects.f fVar = new io.reactivex.rxjava3.subjects.f();
        Trace traceA = com.google.firebase.perf.b.a("LoggedInUserManager_setLoggedInUserFromMemoryCache_trace");
        final Trace traceA2 = com.google.firebase.perf.b.a("LoggedInUserManager_refreshUserData_trace");
        r stopToken = new r();
        this.u = stopToken;
        com.quizlet.data.interactor.school.b bVar = this.o;
        bVar.getClass();
        Intrinsics.checkNotNullParameter(stopToken, "stopToken");
        o0 o0VarB = ((androidx.work.impl.model.c) bVar.c).b(stopToken, new C1510p(bVar, j, 10));
        retrofit2.adapter.rxjava3.d dVar = this.p;
        Objects.requireNonNull(dVar);
        o0VarB.q(new com.google.android.material.search.a(dVar, 26)).u(new a(0, this, traceA), new com.quizlet.billing.subscriptions.c(2), new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.infra.legacysyncengine.managers.b
            @Override // io.reactivex.rxjava3.functions.a
            public final void run() {
                d dVar2 = this.a;
                dVar2.f();
                traceA2.stop();
                com.quizlet.features.infra.studysetting.datasource.a aVar = dVar2.s;
                if (aVar != null) {
                    aVar.g();
                    dVar2.s = null;
                }
                io.reactivex.rxjava3.internal.observers.h hVar = dVar2.t;
                if (hVar != null && !hVar.c()) {
                    io.reactivex.rxjava3.internal.observers.h hVar2 = dVar2.t;
                    hVar2.getClass();
                    io.reactivex.rxjava3.internal.disposables.a.a(hVar2);
                    dVar2.t = null;
                }
                com.quizlet.infra.legacysyncengine.net.c loader = dVar2.k;
                Intrinsics.checkNotNullParameter(loader, "loader");
                com.quizlet.infra.legacysyncengine.orm.b bVar2 = new com.quizlet.infra.legacysyncengine.orm.b(Models.USER);
                bVar2.b(Long.valueOf(j), DBUserFields.ID);
                com.quizlet.features.infra.studysetting.datasource.a aVar2 = new com.quizlet.features.infra.studysetting.datasource.a(loader, bVar2.a());
                dVar2.s = aVar2;
                dVar2.t = (io.reactivex.rxjava3.internal.observers.h) aVar2.f().l(new com.quizlet.baserecyclerview.decoration.a(28)).q(new com.quizlet.baserecyclerview.decoration.a(29)).u(new c(dVar2, 0), io.reactivex.rxjava3.internal.functions.d.e, io.reactivex.rxjava3.internal.functions.d.c);
                fVar.onComplete();
            }
        });
        return fVar;
    }

    public final void c() {
        long j = this.q;
        r stopToken = this.u;
        com.quizlet.data.interactor.school.b bVar = this.o;
        bVar.getClass();
        Intrinsics.checkNotNullParameter(stopToken, "stopToken");
        o0 o0VarB = ((androidx.work.impl.model.c) bVar.c).b(stopToken, new C1510p(bVar, j, 10));
        retrofit2.adapter.rxjava3.d dVar = this.p;
        Objects.requireNonNull(dVar);
        o0VarB.q(new com.google.android.material.search.a(dVar, 26)).u(new c(this, 0), new com.quizlet.billing.subscriptions.c(2), new com.quizlet.eventlogger.e(this, 12));
    }

    public final void d(DBUser dBUser) {
        this.r = dBUser;
        this.q = dBUser != null ? dBUser.getId() : 0L;
        e();
    }

    public final void e() {
        this.l.b(new LoggedInUserStatus(this.q, this.r));
        long j = this.q;
        com.squareup.otto.c cVar = this.a;
        if (j <= 0) {
            cVar.c(new UserLogoutEvent());
        } else {
            cVar.c(new CurrentUserEvent(this.r, j));
        }
    }

    public final void f() {
        if (this.u.s()) {
            return;
        }
        e();
        String lowerCase = Locale.getDefault().toLanguageTag().toLowerCase();
        if (this.r == null || lowerCase.equals("und") || lowerCase.equals(this.r.getMobileLocale())) {
            return;
        }
        this.r.setMobileLocale(lowerCase);
        this.g.a(this.r);
    }

    @com.squareup.otto.h
    public CurrentUserEvent produceCurrentUserEvent() {
        return new CurrentUserEvent(this.r, this.q);
    }
}

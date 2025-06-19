package com.quizlet.quizletandroid;

import com.braze.Braze;
import com.google.android.gms.internal.mlkit_vision_barcode.S6;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.data.model.C4184z;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.metering.StudyModeMeteringEventLogger;
import com.quizlet.eventlogger.features.studymodes.StudyModeEventLogger;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.O;

/* renamed from: com.quizlet.quizletandroid.g, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4624g extends G {
    public final com.google.mlkit.common.sdkinternal.model.a a;
    public final u b;
    public final C4624g c = this;
    public final dagger.internal.c d;
    public final dagger.internal.c e;
    public final dagger.internal.c f;
    public final C4623f g;
    public final dagger.internal.c h;
    public final dagger.internal.c i;
    public final dagger.internal.c j;
    public final dagger.internal.c k;
    public final dagger.internal.c l;
    public final dagger.internal.c m;
    public final dagger.internal.c n;
    public final dagger.internal.c o;
    public final dagger.internal.c p;
    public final dagger.internal.c q;
    public final dagger.internal.c r;
    public final dagger.internal.c s;
    public final dagger.internal.c t;
    public final dagger.internal.c u;
    public final dagger.internal.c v;
    public final dagger.internal.c w;

    public C4624g(u uVar, com.google.mlkit.common.sdkinternal.model.a aVar) {
        this.b = uVar;
        this.a = aVar;
        this.d = dagger.internal.a.b(new C4623f(uVar, this, 0));
        this.e = dagger.internal.a.b(new C4623f(uVar, this, 1));
        this.f = dagger.internal.a.b(new C4623f(uVar, this, 3));
        this.g = new C4623f(uVar, this, 2);
        this.h = dagger.internal.a.b(new C4623f(uVar, this, 4));
        this.i = dagger.internal.a.b(new C4623f(uVar, this, 5));
        this.j = dagger.internal.a.b(new C4623f(uVar, this, 7));
        this.k = dagger.internal.a.b(new C4623f(uVar, this, 6));
        this.l = dagger.internal.a.b(new C4623f(uVar, this, 9));
        this.m = dagger.internal.a.b(new C4623f(uVar, this, 10));
        this.n = dagger.internal.a.b(new C4623f(uVar, this, 8));
        this.o = dagger.internal.a.b(new C4623f(uVar, this, 11));
        this.p = dagger.internal.a.b(new C4623f(uVar, this, 13));
        this.q = dagger.internal.a.b(new C4623f(uVar, this, 14));
        this.r = dagger.internal.a.b(new C4623f(uVar, this, 15));
        this.s = dagger.internal.a.b(new C4623f(uVar, this, 12));
        this.t = dagger.internal.a.b(new C4623f(uVar, this, 16));
        this.u = dagger.internal.a.b(new C4623f(uVar, this, 17));
        this.v = dagger.internal.a.b(new C4623f(uVar, this, 18));
        this.w = dagger.internal.a.b(new C4623f(uVar, this, 19));
    }

    public final com.google.firebase.messaging.p a() {
        return new com.google.firebase.messaging.p(this.b.b());
    }

    public final com.google.firebase.crashlytics.internal.settings.b b() {
        u uVar = this.b;
        return new com.google.firebase.crashlytics.internal.settings.b(new com.quizlet.data.repository.activitycenter.b(uVar.p(), uVar.l0()));
    }

    public final com.quizlet.infra.legacysyncengine.features.properties.d c() {
        u uVar = this.b;
        return new com.quizlet.infra.legacysyncengine.features.properties.d((com.quizlet.infra.legacysyncengine.net.c) uVar.Q.get(), new com.google.firebase.crashlytics.internal.settings.b(new androidx.work.impl.model.v(uVar.o(), u.v())));
    }

    public final com.lyft.android.scissors.b d() {
        u uVar = this.b;
        uVar.getClass();
        Braze braze = (Braze) uVar.W0.get();
        com.quizlet.data.interactor.achievements.f fVarR1 = uVar.r1();
        C4184z c4184z = com.quizlet.quizletandroid.provider.a.a;
        S6.c(c4184z);
        return new com.lyft.android.scissors.b(new com.quizlet.data.repository.activitycenter.b(new com.quizlet.quizletandroid.braze.data.a(braze, fVarR1, c4184z), (com.quizlet.data.connectivity.a) uVar.X.get(), AbstractC4178x.o((org.slf4j.a) uVar.Y.get(), "loggerFactory", com.quizlet.data.repository.activitycenter.b.class, "getLogger(...)")), u.v());
    }

    public final com.quizlet.data.interactor.set.c e() {
        com.quizlet.data.repository.explanations.textbook.a termAndSelectedTermRepository = g();
        this.b.getClass();
        androidx.work.impl.model.c dispatcher = u.v();
        com.quizlet.cache.a requestCache = (com.quizlet.cache.a) this.q.get();
        Intrinsics.checkNotNullParameter(termAndSelectedTermRepository, "termAndSelectedTermRepository");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        Intrinsics.checkNotNullParameter(requestCache, "requestCache");
        com.quizlet.data.interactor.set.c cVar = new com.quizlet.data.interactor.set.c();
        cVar.a = termAndSelectedTermRepository;
        cVar.b = dispatcher;
        cVar.c = requestCache;
        return cVar;
    }

    public final com.quizlet.learn.checkpoint.a f() {
        return new com.quizlet.learn.checkpoint.a(this.b.q());
    }

    public final com.quizlet.data.repository.explanations.textbook.a g() {
        com.quizlet.infra.legacysyncengine.datasources.factory.b termAndSelectedTermDataSourceFactory = (com.quizlet.infra.legacysyncengine.datasources.factory.b) this.p.get();
        com.quizlet.data.connectivity.a networkStatus = (com.quizlet.data.connectivity.a) this.b.X.get();
        Intrinsics.checkNotNullParameter(termAndSelectedTermDataSourceFactory, "termAndSelectedTermDataSourceFactory");
        Intrinsics.checkNotNullParameter(networkStatus, "networkStatus");
        com.quizlet.data.repository.explanations.textbook.a aVar = new com.quizlet.data.repository.explanations.textbook.a();
        aVar.a = termAndSelectedTermDataSourceFactory;
        aVar.b = networkStatus;
        final com.quizlet.quizletandroid.ui.common.ads.G onDataUpdated = new com.quizlet.quizletandroid.ui.common.ads.G(aVar, 15);
        termAndSelectedTermDataSourceFactory.getClass();
        Intrinsics.checkNotNullParameter(onDataUpdated, "onDataUpdated");
        aVar.d = new com.quizlet.infra.legacysyncengine.datasources.b() { // from class: com.quizlet.infra.legacysyncengine.datasources.factory.a
            @Override // com.quizlet.infra.legacysyncengine.datasources.b
            public final void h(List list) {
                onDataUpdated.invoke(list);
            }
        };
        return aVar;
    }

    public final androidx.compose.foundation.text.input.internal.u h() {
        return new androidx.compose.foundation.text.input.internal.u((com.quizlet.features.infra.basestudy.manager.a) this.j.get(), new com.google.firebase.messaging.p(this.b.d1()));
    }

    public final com.quizlet.data.repository.progress.b i() {
        com.quizlet.quizletandroid.ui.studymodes.assistant.studyengine.b bVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.studyengine.b) this.l.get();
        kotlinx.coroutines.scheduling.e eVar = O.a;
        S6.c(eVar);
        return new com.quizlet.data.repository.progress.b(bVar, eVar);
    }

    public final StudyModeEventLogger.Factory j() {
        return new StudyModeEventLogger.Factory((EventLogger) this.b.l0.get());
    }

    public final StudyModeMeteringEventLogger k() {
        return new StudyModeMeteringEventLogger((EventLogger) this.b.l0.get());
    }

    public final androidx.work.impl.model.e l() {
        u uVar = this.b;
        return new androidx.work.impl.model.e(uVar.R(), uVar.m0());
    }
}

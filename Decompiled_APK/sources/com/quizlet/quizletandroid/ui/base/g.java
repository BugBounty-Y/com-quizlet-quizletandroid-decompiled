package com.quizlet.quizletandroid.ui.base;

import android.content.Intent;
import androidx.appcompat.app.AbstractActivityC0055k;
import androidx.lifecycle.X;
import androidx.paging.J0;
import com.facebook.login.E;
import com.google.android.gms.internal.mlkit_vision_barcode.B7;
import com.google.firebase.analytics.FirebaseAnalytics;
import com.google.firebase.crashlytics.internal.common.q;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.quizletandroid.t;
import io.reactivex.rxjava3.core.o;
import io.reactivex.rxjava3.internal.operators.observable.C4887f;
import io.reactivex.rxjava3.internal.operators.observable.W;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlin.u;
import kotlinx.coroutines.InterfaceC5025j0;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes3.dex */
public final class g {
    public final com.quizlet.quizletandroid.managers.audio.h a;
    public final com.squareup.otto.c b;
    public final com.quizlet.baseui.managers.b c;
    public final com.quizlet.quizletandroid.managers.c d;
    public final EventLogger e;
    public final FirebaseAnalytics f;
    public final com.google.firebase.crashlytics.b g;
    public final com.quizlet.quizletandroid.managers.h h;
    public final com.quizlet.data.repository.user.a i;
    public final com.quizlet.infra.legacysyncengine.managers.d j;
    public final b k;
    public final o l;
    public final com.quizlet.data.connectivity.a m;
    public final t n;
    public final t o;
    public final javax.inject.a p;
    public final com.quizlet.usecase.a q;
    public final kotlinx.coroutines.internal.d r;
    public final com.quizlet.features.notes.a s;
    public final X t;
    public final X u;
    public com.quizlet.quizletandroid.ui.base.bus.a v;
    public InterfaceC5025j0 w;
    public long x;

    public g(com.quizlet.quizletandroid.managers.audio.h audioManager, com.squareup.otto.c bus, com.quizlet.baseui.managers.b componentLifecycleDisposableManager, com.quizlet.quizletandroid.managers.c conversionTrackingManager, EventLogger eventLogger, FirebaseAnalytics firebaseAnalytics, com.google.firebase.crashlytics.b firebaseCrashlytics, com.quizlet.quizletandroid.managers.h foregroundMonitor, com.quizlet.data.repository.user.a gaLogger, com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager, b loggingIdResolver, o mainScheduler, com.quizlet.data.connectivity.a networkConnectivityManager, t requestErrorBusListenerProvider, t searchIntentProvider, javax.inject.a oneTrustConsentManager, com.quizlet.usecase.a passwordChangedEventObserver, kotlinx.coroutines.internal.d defaultScope, com.quizlet.features.notes.a widgetsEventLogger) {
        Intrinsics.checkNotNullParameter(audioManager, "audioManager");
        Intrinsics.checkNotNullParameter(bus, "bus");
        Intrinsics.checkNotNullParameter(componentLifecycleDisposableManager, "componentLifecycleDisposableManager");
        Intrinsics.checkNotNullParameter(conversionTrackingManager, "conversionTrackingManager");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        Intrinsics.checkNotNullParameter(firebaseAnalytics, "firebaseAnalytics");
        Intrinsics.checkNotNullParameter(firebaseCrashlytics, "firebaseCrashlytics");
        Intrinsics.checkNotNullParameter(foregroundMonitor, "foregroundMonitor");
        Intrinsics.checkNotNullParameter(gaLogger, "gaLogger");
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        Intrinsics.checkNotNullParameter(loggingIdResolver, "loggingIdResolver");
        Intrinsics.checkNotNullParameter(mainScheduler, "mainScheduler");
        Intrinsics.checkNotNullParameter(networkConnectivityManager, "networkConnectivityManager");
        Intrinsics.checkNotNullParameter(requestErrorBusListenerProvider, "requestErrorBusListenerProvider");
        Intrinsics.checkNotNullParameter(searchIntentProvider, "searchIntentProvider");
        Intrinsics.checkNotNullParameter(oneTrustConsentManager, "oneTrustConsentManager");
        Intrinsics.checkNotNullParameter(passwordChangedEventObserver, "passwordChangedEventObserver");
        Intrinsics.checkNotNullParameter(defaultScope, "defaultScope");
        Intrinsics.checkNotNullParameter(widgetsEventLogger, "widgetsEventLogger");
        this.a = audioManager;
        this.b = bus;
        this.c = componentLifecycleDisposableManager;
        this.d = conversionTrackingManager;
        this.e = eventLogger;
        this.f = firebaseAnalytics;
        this.g = firebaseCrashlytics;
        this.h = foregroundMonitor;
        this.i = gaLogger;
        this.j = loggedInUserManager;
        this.k = loggingIdResolver;
        this.l = mainScheduler;
        this.m = networkConnectivityManager;
        this.n = requestErrorBusListenerProvider;
        this.o = searchIntentProvider;
        this.p = oneTrustConsentManager;
        this.q = passwordChangedEventObserver;
        this.r = defaultScope;
        this.s = widgetsEventLogger;
        this.t = new X(1);
        this.u = new X(1);
    }

    public final void a(AbstractActivityC0055k activity, boolean z) {
        Intrinsics.checkNotNullParameter(activity, "activity");
        this.a.b(true);
        com.quizlet.quizletandroid.ui.base.bus.a aVar = this.v;
        if (aVar != null) {
            com.squareup.otto.c cVar = this.b;
            cVar.d.a(cVar);
            com.squareup.otto.g gVar = cVar.e;
            for (Map.Entry entry : gVar.b(aVar).entrySet()) {
                Class cls = (Class) entry.getKey();
                ConcurrentHashMap concurrentHashMap = cVar.b;
                com.squareup.otto.f fVar = (com.squareup.otto.f) concurrentHashMap.get(cls);
                com.squareup.otto.f fVar2 = (com.squareup.otto.f) entry.getValue();
                if (fVar2 == null || !fVar2.equals(fVar)) {
                    throw new IllegalArgumentException("Missing event producer for an annotated method. Is " + com.quizlet.quizletandroid.ui.base.bus.a.class + " registered?");
                }
                ((com.squareup.otto.f) concurrentHashMap.remove(cls)).d = false;
            }
            for (Map.Entry entry2 : gVar.c(aVar).entrySet()) {
                Set<com.squareup.otto.e> set = (Set) cVar.a.get((Class) entry2.getKey());
                Collection<?> collection = (Collection) entry2.getValue();
                if (set == null || !set.containsAll(collection)) {
                    throw new IllegalArgumentException("Missing event handler for an annotated method. Is " + com.quizlet.quizletandroid.ui.base.bus.a.class + " registered?");
                }
                for (com.squareup.otto.e eVar : set) {
                    if (collection.contains(eVar)) {
                        eVar.d = false;
                    }
                }
                set.removeAll(collection);
            }
            this.v = null;
            InterfaceC5025j0 interfaceC5025j0 = this.w;
            if (interfaceC5025j0 != null) {
                interfaceC5025j0.j(null);
            }
            this.w = null;
        }
        this.e.A(this.k.a(activity), assistantMode.refactored.a.f() - this.x, z);
    }

    public final void b(AbstractActivityC0055k activity) {
        Intrinsics.checkNotNullParameter(activity, "activity");
        com.quizlet.infra.legacysyncengine.managers.d dVar = this.j;
        io.reactivex.rxjava3.subjects.d dVar2 = dVar.l;
        dVar2.getClass();
        C4887f c4887f = new C4887f(new C4887f(dVar2, 1).q(new com.quizlet.local.ormlite.models.term.b(f.a)), 1);
        Intrinsics.checkNotNullExpressionValue(c4887f, "distinctUntilChanged(...)");
        io.reactivex.rxjava3.internal.observers.h disposable = B7.d(c4887f, new com.quizlet.login.common.navigation.d(1, timber.log.c.a, timber.log.a.class, "e", "e(Ljava/lang/Throwable;)V", 0, 17), null, new c(this, 1), 2);
        com.quizlet.baseui.managers.b manager = this.c;
        Intrinsics.checkNotNullParameter(disposable, "<this>");
        Intrinsics.checkNotNullParameter(manager, "manager");
        Intrinsics.checkNotNullParameter(disposable, "disposable");
        u uVar = manager.d;
        Object value = uVar.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        ((io.reactivex.rxjava3.disposables.a) value).b(disposable);
        if (activity instanceof com.quizlet.features.consent.onetrust.b) {
            return;
        }
        io.reactivex.rxjava3.internal.operators.single.g gVarG = dVar.a().g(new com.quizlet.local.ormlite.models.term.b(d.a));
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        io.reactivex.rxjava3.internal.observers.e disposable2 = B7.b(gVarG, io.reactivex.rxjava3.kotlin.c.b, new com.quizlet.features.setpage.header.ui.g(11, activity, this));
        Intrinsics.checkNotNullParameter(disposable2, "<this>");
        Intrinsics.checkNotNullParameter(manager, "manager");
        Intrinsics.checkNotNullParameter(disposable2, "disposable");
        Object value2 = uVar.getValue();
        Intrinsics.checkNotNullExpressionValue(value2, "getValue(...)");
        ((io.reactivex.rxjava3.disposables.a) value2).b(disposable2);
    }

    /* JADX WARN: Type inference failed for: r12v20, types: [kotlinx.coroutines.flow.i, kotlinx.coroutines.flow.internal.a] */
    public final void c(AbstractActivityC0055k activity, String identity, boolean z) {
        Intrinsics.checkNotNullParameter(activity, "activity");
        Intrinsics.checkNotNullParameter(identity, "identity");
        q qVar = this.g.a;
        qVar.o.a.a(new E(qVar, "last_screen_viewed", identity, 1));
        if (this.v == null) {
            com.quizlet.quizletandroid.ui.base.bus.a aVar = (com.quizlet.quizletandroid.ui.base.bus.a) this.n.get();
            this.v = aVar;
            this.b.d(aVar);
            InterfaceC5025j0 interfaceC5025j0 = this.w;
            if (interfaceC5025j0 != null) {
                interfaceC5025j0.j(null);
            }
            this.w = e0.w(new J0(this.q.a, new e(this, null), 5), this.r);
        }
        com.quizlet.remote.connectivity.a aVar2 = ((com.quizlet.remote.connectivity.b) this.m).a;
        W wS = aVar2.a.s(this.l);
        Intrinsics.checkNotNullExpressionValue(wS, "observeOn(...)");
        io.reactivex.rxjava3.internal.observers.h disposable = B7.d(wS, new com.quizlet.login.common.navigation.d(1, timber.log.c.a, timber.log.a.class, "e", "e(Ljava/lang/Throwable;)V", 0, 16), null, new c(this, 0), 2);
        Intrinsics.checkNotNullParameter(disposable, "<this>");
        com.quizlet.baseui.managers.b manager = this.c;
        Intrinsics.checkNotNullParameter(manager, "manager");
        Intrinsics.checkNotNullParameter(disposable, "disposable");
        Object value = manager.b.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        ((io.reactivex.rxjava3.disposables.a) value).b(disposable);
        this.t.j(Unit.a);
        com.quizlet.quizletandroid.managers.c cVar = this.d;
        if (!cVar.c) {
            cVar.b();
            cVar.c = true;
        }
        this.e.B(this.k.a(activity), z);
        this.x = System.currentTimeMillis();
        Intent intent = activity.getIntent();
        Intrinsics.checkNotNullExpressionValue(intent, "getIntent(...)");
        this.s.a(intent);
    }

    public final void d(String screenName, boolean z) {
        Intrinsics.checkNotNullParameter(screenName, "identity");
        com.quizlet.quizletandroid.managers.h hVar = this.h;
        int i = hVar.a + 1;
        hVar.a = i;
        if (i == 1) {
            hVar.b.b(Boolean.TRUE);
        }
        if (z) {
            com.quizlet.data.repository.user.a aVar = this.i;
            Intrinsics.checkNotNullParameter(screenName, "screenName");
            ((com.quizlet.infra.legacysyncengine.managers.d) aVar.b).a().i(new com.quizlet.quizletandroid.logging.ga.a(aVar, screenName, null, null, null, null), new com.quizlet.billing.manager.d(timber.log.c.a, 7));
        }
    }
}

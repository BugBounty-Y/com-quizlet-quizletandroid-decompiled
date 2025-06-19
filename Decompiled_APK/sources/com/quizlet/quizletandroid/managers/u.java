package com.quizlet.quizletandroid.managers;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ShortcutManager;
import android.webkit.CookieManager;
import androidx.appcompat.app.AbstractC0061q;
import com.appsflyer.AppsFlyerLib;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.local.datastore.preferences.C4567d;
import com.quizlet.local.datastore.preferences.C4574j;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class u {
    public final com.quizlet.infra.legacysyncengine.managers.d a;
    public final DatabaseHelper b;
    public final com.quizlet.data.repository.set.f c;
    public final com.quizlet.local.cache.caches.a d;
    public final com.quizlet.quizletandroid.managers.audio.h e;
    public final com.quizlet.billing.subscriptions.h f;
    public final com.google.android.gms.internal.appset.e g;
    public final com.quizlet.data.repository.classfolder.e h;
    public final com.quizlet.quizletandroid.t i;
    public final com.quizlet.data.repository.widget.b j;
    public final com.google.android.material.floatingactionbutton.c k;
    public final ShortcutManager l;
    public final AbstractC5040y m;
    public final com.google.android.material.floatingactionbutton.c n;
    public final com.quizlet.usecase.b o;
    public final com.google.firebase.messaging.p p;
    public final com.quizlet.shared.usecase.session.b q;
    public final com.google.firebase.crashlytics.internal.common.j r;
    public final C4567d s;
    public final C4574j t;
    public final Context u;
    public final com.quizlet.data.interactor.achievements.f v;
    public final CookieManager w;
    public final kotlinx.coroutines.internal.d x;
    public final kotlinx.coroutines.internal.d y;

    public u(com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager, DatabaseHelper databaseHelper, com.quizlet.data.repository.set.f nightThemeManager, com.quizlet.local.cache.caches.a achievementsCache, com.quizlet.quizletandroid.managers.audio.h audioManager, com.quizlet.billing.subscriptions.h subscriptionHandler, com.google.android.gms.internal.appset.e scanDocumentManager, com.quizlet.data.repository.classfolder.e marketingAnalyticsManager, com.quizlet.quizletandroid.t introIntentProvider, com.quizlet.data.repository.widget.b googleAuthenticationProxy, com.google.android.material.floatingactionbutton.c signOutWithGoogleManager, ShortcutManager shortcutManager, kotlinx.coroutines.scheduling.e defaultDispatcher, AbstractC5040y ioDispatcher, com.google.android.material.floatingactionbutton.c notesPreferencesStoreManager, com.quizlet.usecase.b userUseCase, com.google.firebase.messaging.p clearUserFeatureEligibilityUseCase, com.quizlet.shared.usecase.session.b onLogoutHandler, com.google.firebase.crashlytics.internal.common.j libraryPreferencesDataStore, C4567d termListPreferencesStoreManager, C4574j clearGlobalCacheDataStoreUtil, Context context, com.quizlet.data.interactor.achievements.f facebookLoginManagerProvider, CookieManager cookieManager) {
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        Intrinsics.checkNotNullParameter(databaseHelper, "databaseHelper");
        Intrinsics.checkNotNullParameter(nightThemeManager, "nightThemeManager");
        Intrinsics.checkNotNullParameter(achievementsCache, "achievementsCache");
        Intrinsics.checkNotNullParameter(audioManager, "audioManager");
        Intrinsics.checkNotNullParameter(subscriptionHandler, "subscriptionHandler");
        Intrinsics.checkNotNullParameter(scanDocumentManager, "scanDocumentManager");
        Intrinsics.checkNotNullParameter(marketingAnalyticsManager, "marketingAnalyticsManager");
        Intrinsics.checkNotNullParameter(introIntentProvider, "introIntentProvider");
        Intrinsics.checkNotNullParameter(googleAuthenticationProxy, "googleAuthenticationProxy");
        Intrinsics.checkNotNullParameter(signOutWithGoogleManager, "signOutWithGoogleManager");
        Intrinsics.checkNotNullParameter(shortcutManager, "shortcutManager");
        Intrinsics.checkNotNullParameter(defaultDispatcher, "defaultDispatcher");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        Intrinsics.checkNotNullParameter(notesPreferencesStoreManager, "notesPreferencesStoreManager");
        Intrinsics.checkNotNullParameter(userUseCase, "userUseCase");
        Intrinsics.checkNotNullParameter(clearUserFeatureEligibilityUseCase, "clearUserFeatureEligibilityUseCase");
        Intrinsics.checkNotNullParameter(onLogoutHandler, "onLogoutHandler");
        Intrinsics.checkNotNullParameter(libraryPreferencesDataStore, "libraryPreferencesDataStore");
        Intrinsics.checkNotNullParameter(termListPreferencesStoreManager, "termListPreferencesStoreManager");
        Intrinsics.checkNotNullParameter(clearGlobalCacheDataStoreUtil, "clearGlobalCacheDataStoreUtil");
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(facebookLoginManagerProvider, "facebookLoginManagerProvider");
        Intrinsics.checkNotNullParameter(cookieManager, "cookieManager");
        this.a = loggedInUserManager;
        this.b = databaseHelper;
        this.c = nightThemeManager;
        this.d = achievementsCache;
        this.e = audioManager;
        this.f = subscriptionHandler;
        this.g = scanDocumentManager;
        this.h = marketingAnalyticsManager;
        this.i = introIntentProvider;
        this.j = googleAuthenticationProxy;
        this.k = signOutWithGoogleManager;
        this.l = shortcutManager;
        this.m = ioDispatcher;
        this.n = notesPreferencesStoreManager;
        this.o = userUseCase;
        this.p = clearUserFeatureEligibilityUseCase;
        this.q = onLogoutHandler;
        this.r = libraryPreferencesDataStore;
        this.s = termListPreferencesStoreManager;
        this.t = clearGlobalCacheDataStoreUtil;
        this.u = context;
        this.v = facebookLoginManagerProvider;
        this.w = cookieManager;
        this.x = E.c(defaultDispatcher);
        this.y = E.c(ioDispatcher);
    }

    /* JADX WARN: Type inference failed for: r1v13, types: [io.reactivex.rxjava3.disposables.b, java.util.concurrent.atomic.AtomicReference] */
    public final void a() {
        com.quizlet.infra.legacysyncengine.managers.d dVar = this.a;
        dVar.getClass();
        timber.log.a aVar = timber.log.c.a;
        aVar.d("Logging out", new Object[0]);
        dVar.h.e().l(dVar.i).h(dVar.j).i(new com.quizlet.infra.legacysyncengine.managers.c(dVar, 1), new com.quizlet.infra.legacysyncengine.managers.c(dVar, 2));
        io.reactivex.rxjava3.subjects.r rVar = dVar.u;
        Unit unit = Unit.a;
        rVar.onSuccess(unit);
        com.quizlet.features.infra.studysetting.datasource.a aVar2 = dVar.s;
        if (aVar2 != null) {
            aVar2.g();
            dVar.s = null;
        }
        io.reactivex.rxjava3.internal.observers.h hVar = dVar.t;
        if (hVar != null && !hVar.c()) {
            io.reactivex.rxjava3.internal.observers.h hVar2 = dVar.t;
            hVar2.getClass();
            io.reactivex.rxjava3.internal.disposables.a.a(hVar2);
            dVar.t = null;
        }
        dVar.d(null);
        HashSet groupIds = new HashSet();
        com.quizlet.features.setpage.upsell.a aVar3 = dVar.d;
        aVar3.getClass();
        Intrinsics.checkNotNullParameter(groupIds, "groupIds");
        aVar3.a.edit().putString("group_id", CollectionsKt.S(groupIds, ",", null, null, null, 62)).apply();
        dVar.n.a.edit().clear().apply();
        aVar.d("Nulled preferences", new Object[0]);
        dVar.u.onSuccess(unit);
        com.quizlet.infra.legacysyncengine.net.listeners.d dVar2 = dVar.k.b;
        dVar2.c.clear();
        dVar2.a.b.clear();
        aVar.d("Aborted loaders", new Object[0]);
        DatabaseHelper databaseHelper = dVar.b;
        databaseHelper.getClass();
        try {
            databaseHelper.f(new androidx.work.impl.utils.d(databaseHelper, 9));
        } catch (SQLException e) {
            timber.log.c.a(e);
        }
        timber.log.c.a.d("Deleted tables", new Object[0]);
        com.quizlet.data.repository.widget.b bVar = this.j;
        ((com.google.android.gms.internal.p000authapi.b) bVar.b).e();
        ((com.google.android.gms.auth.api.signin.a) bVar.c).d();
        ((SharedPreferences) this.c.c).edit().clear().apply();
        AbstractC0061q.k(-1);
        ((com.quizlet.scandocument.ui.d) this.g.b).a.edit().clear().apply();
        com.quizlet.local.cache.caches.a aVar4 = this.d;
        aVar4.a.b.clear();
        aVar4.b.b.clear();
        aVar4.c.b.clear();
        aVar4.d.b.clear();
        com.quizlet.quizletandroid.managers.audio.h hVar3 = this.e;
        hVar3.b.c();
        hVar3.a.b.a();
        com.quizlet.data.repository.classfolder.e eVar = this.h;
        boolean z = com.quizlet.analytics.marketing.appsflyer.e.b;
        com.quizlet.analytics.marketing.appsflyer.e eVar2 = (com.quizlet.analytics.marketing.appsflyer.e) eVar.c;
        if (z) {
            AppsFlyerLib appsFlyerLib = AppsFlyerLib.getInstance();
            Intrinsics.checkNotNullExpressionValue(appsFlyerLib, "getInstance(...)");
            if (!appsFlyerLib.isStopped()) {
                AppsFlyerLib appsFlyerLib2 = AppsFlyerLib.getInstance();
                Intrinsics.checkNotNullExpressionValue(appsFlyerLib2, "getInstance(...)");
                appsFlyerLib2.stop(true, eVar2.a);
            }
        }
        ((AtomicReference) eVar.d).dispose();
        eVar.d = new io.reactivex.rxjava3.disposables.d(io.reactivex.rxjava3.internal.functions.d.b, 0);
        com.quizlet.data.repository.classfolder.e.e = null;
        this.l.removeAllDynamicShortcuts();
        m mVar = new m(this, null);
        kotlinx.coroutines.internal.d dVar3 = this.y;
        E.A(dVar3, null, null, mVar, 3);
        E.A(dVar3, null, null, new s(this, null), 3);
        E.A(dVar3, null, null, new l(this, null), 3);
        E.A(dVar3, null, null, new p(this, null), 3);
        E.A(dVar3, null, null, new k(this, null), 3);
        E.A(dVar3, null, null, new n(this, null), 3);
        E.A(dVar3, null, null, new j(this, null), 3);
        i iVar = new i(this, null);
        kotlinx.coroutines.internal.d dVar4 = this.x;
        E.A(dVar4, null, null, iVar, 3);
        ((com.quizlet.usecase.a) this.o).a(null);
        E.A(dVar4, null, null, new o(this, null), 3);
    }

    /* JADX WARN: Code restructure failed: missing block: B:19:0x004b, code lost:
    
        if (r7.d.d(r7.b.e().a) != false) goto L20;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Enum b(boolean r7, kotlin.coroutines.jvm.internal.c r8) throws java.lang.Throwable {
        /*
            r6 = this;
            boolean r0 = r8 instanceof com.quizlet.quizletandroid.managers.q
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.quizletandroid.managers.q r0 = (com.quizlet.quizletandroid.managers.q) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.quizletandroid.managers.q r0 = new com.quizlet.quizletandroid.managers.q
            r0.<init>(r6, r8)
        L18:
            java.lang.Object r8 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L6b
        L27:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r8 = 0
            if (r7 != 0) goto L5b
            com.quizlet.billing.subscriptions.h r7 = r6.f
            com.quizlet.billing.manager.f r2 = r7.i
            boolean r2 = r2.j
            if (r2 != 0) goto L4d
            com.lyft.android.scissors.b r2 = r7.b
            com.quizlet.billing.model.b r2 = r2.e()
            com.quizlet.billing.register.a r7 = r7.d
            long r4 = r2.a
            boolean r7 = r7.d(r4)
            if (r7 == 0) goto L5b
        L4d:
            com.quizlet.quizletandroid.managers.t r7 = new com.quizlet.quizletandroid.managers.t
            r7.<init>(r6, r8)
            r0 = 3
            kotlinx.coroutines.internal.d r1 = r6.y
            kotlinx.coroutines.E.A(r1, r8, r8, r7, r0)
            com.quizlet.data.model.t0 r7 = com.quizlet.data.model.EnumC4167t0.b
            return r7
        L5b:
            com.quizlet.quizletandroid.managers.r r7 = new com.quizlet.quizletandroid.managers.r
            r7.<init>(r6, r8)
            r0.l = r3
            kotlinx.coroutines.y r8 = r6.m
            java.lang.Object r8 = kotlinx.coroutines.E.J(r8, r7, r0)
            if (r8 != r1) goto L6b
            return r1
        L6b:
            java.lang.Boolean r8 = (java.lang.Boolean) r8
            boolean r7 = r8.booleanValue()
            if (r7 == 0) goto L76
            com.quizlet.data.model.t0 r7 = com.quizlet.data.model.EnumC4167t0.c
            return r7
        L76:
            com.quizlet.data.model.t0 r7 = com.quizlet.data.model.EnumC4167t0.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.managers.u.b(boolean, kotlin.coroutines.jvm.internal.c):java.lang.Enum");
    }
}

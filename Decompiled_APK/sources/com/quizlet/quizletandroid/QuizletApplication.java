package com.quizlet.quizletandroid;

import androidx.appcompat.app.AbstractC0061q;
import androidx.work.InterfaceC1421b;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.google.android.gms.internal.mlkit_vision_camera.A2;
import com.google.firebase.perf.metrics.Trace;
import com.j256.ormlite.dao.DaoManager;
import com.j256.ormlite.field.DatabaseFieldConfig;
import com.j256.ormlite.table.DatabaseTableConfig;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.billing.model.DBSubscription;
import com.quizlet.db.data.models.legacy.LegacyFavoriteSet$$Configuration;
import com.quizlet.db.data.models.legacy.LegacyFeedItem$$Configuration;
import com.quizlet.db.data.models.legacy.LegacyFeedResponseWrapper$$Configuration;
import com.quizlet.db.data.models.legacy.LegacyGroupMembership$$Configuration;
import com.quizlet.db.data.models.legacy.LegacyGroupWrapper$$Configuration;
import com.quizlet.db.data.models.legacy.LegacySession$$Configuration;
import com.quizlet.db.data.models.legacy.LegacyUser$$Configuration;
import com.quizlet.db.data.models.persisted.DBAnswer$$Configuration;
import com.quizlet.db.data.models.persisted.DBBookmark$$Configuration;
import com.quizlet.db.data.models.persisted.DBDiagramShape$$Configuration;
import com.quizlet.db.data.models.persisted.DBEnteredSetPassword$$Configuration;
import com.quizlet.db.data.models.persisted.DBFolder$$Configuration;
import com.quizlet.db.data.models.persisted.DBGroup$$Configuration;
import com.quizlet.db.data.models.persisted.DBGroupFolder$$Configuration;
import com.quizlet.db.data.models.persisted.DBGroupMembership$$Configuration;
import com.quizlet.db.data.models.persisted.DBGroupSet$$Configuration;
import com.quizlet.db.data.models.persisted.DBImage$$Configuration;
import com.quizlet.db.data.models.persisted.DBImageRef$$Configuration;
import com.quizlet.db.data.models.persisted.DBOfflineEntity$$Configuration;
import com.quizlet.db.data.models.persisted.DBProgressReset$$Configuration;
import com.quizlet.db.data.models.persisted.DBQuestionAttribute$$Configuration;
import com.quizlet.db.data.models.persisted.DBSchool$$Configuration;
import com.quizlet.db.data.models.persisted.DBSelectedTerm$$Configuration;
import com.quizlet.db.data.models.persisted.DBSession$$Configuration;
import com.quizlet.db.data.models.persisted.DBStudySet$$Configuration;
import com.quizlet.db.data.models.persisted.DBStudySetting$$Configuration;
import com.quizlet.db.data.models.persisted.DBTerm$$Configuration;
import com.quizlet.db.data.models.persisted.DBUser$$Configuration;
import com.quizlet.db.data.models.persisted.DBUserStudyable$$Configuration;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import com.quizlet.quizletandroid.ui.common.ads.C4636c;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import org.koin.core.error.DefinitionOverrideException;
import org.koin.core.error.KoinAppAlreadyStartedException;

/* loaded from: classes3.dex */
public class QuizletApplication extends D implements dagger.android.c, InterfaceC1421b {
    public static final /* synthetic */ int m = 0;
    public com.squareup.otto.c c;
    public com.quizlet.data.repository.widget.b d;
    public C4636c e;
    public dagger.internal.c f;
    public androidx.hilt.work.a g;
    public androidx.compose.runtime.internal.j h;
    public kotlinx.coroutines.internal.d i;
    public dagger.internal.a j;
    public com.quizlet.quizletandroid.logging.b k;
    public AtomicReference l = new io.reactivex.rxjava3.disposables.d(io.reactivex.rxjava3.internal.functions.d.b, 0);

    @Override // dagger.android.c
    public final C4636c c() {
        return this.e;
    }

    @Override // com.quizlet.quizletandroid.D, android.app.Application
    public final void onCreate() throws DefinitionOverrideException, IllegalAccessException, KoinAppAlreadyStartedException, SecurityException, IllegalArgumentException {
        Trace traceA = com.google.firebase.perf.b.a("startup_onCreateApplicationTrace");
        System.setProperty("rx3.computation-priority", "3");
        System.setProperty("rx3.io-priority", "4");
        System.setProperty("rx3.single-priority", "4");
        Trace traceA2 = com.google.firebase.perf.b.a("startup_superOnCreate");
        super.onCreate();
        traceA2.stop();
        androidx.compose.runtime.internal.j jVar = this.h;
        jVar.getClass();
        Trace traceA3 = com.google.firebase.perf.b.a("startup_ApplicationDependencyInitializer_init");
        Intrinsics.checkNotNullParameter(this, "application");
        com.quizlet.local.ormlite.models.term.b bVar = (com.quizlet.local.ormlite.models.term.b) jVar.a;
        bVar.getClass();
        Trace traceA4 = com.google.firebase.perf.b.a("startup_initializeLoggingTrace");
        timber.log.a aVar = timber.log.c.a;
        com.quizlet.android.logging.a tree = (com.quizlet.android.logging.a) bVar.b;
        aVar.getClass();
        Intrinsics.checkNotNullParameter(tree, "tree");
        if (tree == aVar) {
            throw new IllegalArgumentException("Cannot plant Timber into itself.");
        }
        ArrayList arrayList = timber.log.c.b;
        synchronized (arrayList) {
            arrayList.add(tree);
            Object[] array = arrayList.toArray(new timber.log.b[0]);
            if (array == null) {
                throw new NullPointerException("null cannot be cast to non-null type kotlin.Array<T>");
            }
            timber.log.c.c = (timber.log.b[]) array;
            Unit unit = Unit.a;
        }
        traceA4.stop();
        com.quizlet.infra.legacysyncengine.net.request.g gVar = (com.quizlet.infra.legacysyncengine.net.request.g) jVar.b;
        Trace traceA5 = com.google.firebase.perf.b.a("startup_setupRxErrorHandler");
        C7.a = gVar;
        traceA5.stop();
        Trace traceA6 = com.google.firebase.perf.b.a("startup_OrmLiteInit");
        System.setProperty("com.j256.ormlite.logger.type", "ANDROID");
        ArrayList arrayList2 = new ArrayList();
        DatabaseTableConfig databaseTableConfigG = AbstractC4178x.g(DBSubscription.class, DBSubscription.TABLE_NAME);
        ArrayList arrayList3 = new ArrayList();
        DatabaseFieldConfig databaseFieldConfig = new DatabaseFieldConfig();
        databaseFieldConfig.setFieldName("dirty");
        databaseFieldConfig.setColumnName("dirty");
        int i = 2;
        databaseFieldConfig.setMaxForeignAutoRefreshLevel(2);
        arrayList3.add(databaseFieldConfig);
        DatabaseFieldConfig databaseFieldConfig2 = new DatabaseFieldConfig();
        databaseFieldConfig2.setFieldName("isDeleted");
        DatabaseFieldConfig databaseFieldConfigT = AbstractC4178x.t(databaseFieldConfig2, 2, arrayList3, databaseFieldConfig2, "isDeleted");
        AbstractC4178x.q(databaseFieldConfigT, "lastModified", "lastModified", 2);
        arrayList3.add(databaseFieldConfigT);
        DatabaseFieldConfig databaseFieldConfig3 = new DatabaseFieldConfig();
        databaseFieldConfig3.setFieldName(BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        databaseFieldConfig3.setColumnName(BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        databaseFieldConfig3.setMaxForeignAutoRefreshLevel(2);
        arrayList3.add(databaseFieldConfig3);
        databaseTableConfigG.setFieldConfigs(arrayList3);
        arrayList2.add(databaseTableConfigG);
        arrayList2.add(LegacyFavoriteSet$$Configuration.getTableConfig());
        arrayList2.add(LegacyFeedItem$$Configuration.getTableConfig());
        arrayList2.add(LegacyFeedResponseWrapper$$Configuration.getTableConfig());
        arrayList2.add(LegacyGroupMembership$$Configuration.getTableConfig());
        arrayList2.add(LegacyGroupWrapper$$Configuration.getTableConfig());
        arrayList2.add(LegacySession$$Configuration.getTableConfig());
        arrayList2.add(LegacyUser$$Configuration.getTableConfig());
        arrayList2.add(DBAnswer$$Configuration.getTableConfig());
        arrayList2.add(DBBookmark$$Configuration.getTableConfig());
        arrayList2.add(DBDiagramShape$$Configuration.getTableConfig());
        arrayList2.add(DBEnteredSetPassword$$Configuration.getTableConfig());
        arrayList2.add(DBFolder$$Configuration.getTableConfig());
        arrayList2.add(DBGroup$$Configuration.getTableConfig());
        arrayList2.add(DBGroupFolder$$Configuration.getTableConfig());
        arrayList2.add(DBGroupMembership$$Configuration.getTableConfig());
        arrayList2.add(DBGroupSet$$Configuration.getTableConfig());
        arrayList2.add(DBImage$$Configuration.getTableConfig());
        arrayList2.add(DBImageRef$$Configuration.getTableConfig());
        arrayList2.add(DBOfflineEntity$$Configuration.getTableConfig());
        arrayList2.add(DBProgressReset$$Configuration.getTableConfig());
        arrayList2.add(DBQuestionAttribute$$Configuration.getTableConfig());
        arrayList2.add(DBSchool$$Configuration.getTableConfig());
        arrayList2.add(DBSelectedTerm$$Configuration.getTableConfig());
        arrayList2.add(DBSession$$Configuration.getTableConfig());
        arrayList2.add(DBStudySet$$Configuration.getTableConfig());
        arrayList2.add(DBStudySetting$$Configuration.getTableConfig());
        arrayList2.add(DBTerm$$Configuration.getTableConfig());
        arrayList2.add(DBUser$$Configuration.getTableConfig());
        arrayList2.add(DBUserStudyable$$Configuration.getTableConfig());
        DaoManager.addCachedDatabaseConfigs(arrayList2);
        traceA6.stop();
        Trace traceA7 = com.google.firebase.perf.b.a("startup_InAppBillingManagerSetup");
        ((com.quizlet.billing.manager.f) jVar.d).c();
        traceA7.stop();
        Trace traceA8 = com.google.firebase.perf.b.a("startup_applyNightTheme");
        int iOrdinal = ((com.quizlet.data.repository.set.f) jVar.i).n().ordinal();
        if (iOrdinal == 0) {
            i = -1;
        } else if (iOrdinal == 1) {
            i = 1;
        } else if (iOrdinal != 2) {
            throw new NoWhenBranchMatchedException();
        }
        AbstractC0061q.k(i);
        traceA8.stop();
        Trace traceA9 = com.google.firebase.perf.b.a("startup_launchKmpMobile");
        C1608n mobileKmpDependencyProvider = (C1608n) jVar.h;
        Intrinsics.checkNotNullParameter(mobileKmpDependencyProvider, "mobileKmpDependencyProvider");
        List modules = kotlin.collections.B.j(A2.b(new androidx.credentials.playservices.controllers.BeginSignIn.c(mobileKmpDependencyProvider, 15)), com.quizlet.shared.usecase.di.e.a, com.quizlet.shared.usecase.di.g.a, assistantMode.di.c.a);
        Intrinsics.checkNotNullParameter(modules, "modules");
        com.quizlet.data.repository.login.a aVar2 = com.quizlet.shared.di.a.a;
        if (aVar2 != null) {
            aVar2.k(modules, true);
        } else {
            com.quizlet.assembly.compose.menu.e appDeclaration = new com.quizlet.assembly.compose.menu.e(modules, 26);
            Intrinsics.checkNotNullParameter(appDeclaration, "appDeclaration");
            org.koin.core.a aVar3 = new org.koin.core.a();
            if (com.quizlet.shared.di.a.a != null) {
                Intrinsics.checkNotNullParameter("A Koin Application has already been started", "msg");
                throw new KoinAppAlreadyStartedException("A Koin Application has already been started");
            }
            com.quizlet.shared.di.a.a = aVar3.a;
            aVar3.b = true;
            appDeclaration.invoke(aVar3);
        }
        traceA9.stop();
        kotlinx.coroutines.E.A((kotlinx.coroutines.internal.d) jVar.j, null, null, new C4593a(jVar, this, null), 3);
        traceA3.stop();
        this.h = null;
        Trace traceA10 = com.google.firebase.perf.b.a("startup_applicationLoggingTrace");
        com.quizlet.quizletandroid.logging.b bVar2 = this.k;
        bVar2.getClass();
        Intrinsics.checkNotNullParameter(this, "application");
        kotlinx.coroutines.E.A(bVar2.a, null, null, new com.quizlet.quizletandroid.logging.a(bVar2, this, null), 3);
        this.k = null;
        traceA10.stop();
        Trace traceA11 = com.google.firebase.perf.b.a("startup_registerBusTrace");
        this.c.d(new E(this));
        traceA11.stop();
        traceA.stop();
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [io.reactivex.rxjava3.disposables.b, java.util.concurrent.atomic.AtomicReference] */
    @Override // android.app.Application
    public final void onTerminate() {
        super.onTerminate();
        this.l.dispose();
    }

    @Override // android.app.Application, android.content.ComponentCallbacks2
    public final void onTrimMemory(int i) {
        try {
            com.quizlet.quizletandroid.util.h hVar = (com.quizlet.quizletandroid.util.h) this.j.get();
            kotlinx.coroutines.internal.d scope = this.i;
            Intrinsics.checkNotNullParameter(hVar, "<this>");
            Intrinsics.checkNotNullParameter(scope, "scope");
            kotlinx.coroutines.E.A(scope, null, null, new com.quizlet.quizletandroid.util.i(hVar, i, null), 3);
        } catch (NullPointerException unused) {
        }
        super.onTrimMemory(i);
    }
}

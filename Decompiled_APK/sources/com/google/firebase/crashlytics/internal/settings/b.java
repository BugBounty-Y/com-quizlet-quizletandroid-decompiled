package com.google.firebase.crashlytics.internal.settings;

import android.content.Context;
import android.net.Uri;
import android.os.SystemClock;
import android.util.Log;
import androidx.camera.camera2.internal.C0138o;
import androidx.datastore.core.InterfaceC1076h;
import androidx.work.impl.model.l;
import androidx.work.impl.model.v;
import com.comscore.streaming.EventType;
import com.facebook.z;
import com.google.android.gms.common.Feature;
import com.google.android.gms.common.api.internal.k;
import com.google.android.gms.internal.ads.AbstractC2027eu;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3728t4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3762x6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.T3;
import com.google.android.gms.measurement.internal.N;
import com.google.android.gms.tasks.n;
import com.j256.ormlite.dao.Dao;
import com.onetrust.otpublishers.headless.UI.fragment.q;
import com.quizlet.ads.ui.widgets.f;
import com.quizlet.api.model.ApiResponse;
import com.quizlet.api.model.ApiThreeWrapper;
import com.quizlet.api.model.ISkuDetails;
import com.quizlet.api.model.ModelWrapper;
import com.quizlet.data.model.User;
import com.quizlet.data.model.Z1;
import com.quizlet.data.repository.folderwithcreatorinclass.e;
import com.quizlet.data.repository.studysetwithcreatorinclass.g;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.identity.ModelIdentityProvider;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.features.setpage.terms.ui.SelectedTermsModeFragment;
import com.quizlet.generated.enums.G1;
import com.quizlet.generated.enums.I0;
import com.quizlet.infra.legacysyncengine.datasources.w;
import com.quizlet.local.datastore.preferences.C4566c0;
import com.quizlet.uicommon.ui.common.widgets.i;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.internal.operators.completable.m;
import io.reactivex.rxjava3.internal.operators.observable.E;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.u;
import org.json.JSONObject;
import retrofit2.K;

/* loaded from: classes2.dex */
public final class b implements f, ISkuDetails, h, com.quizlet.uicommon.ui.common.widgets.h, com.quizlet.local.ormlite.database.b {
    public final /* synthetic */ int a;
    public Object b;

    public /* synthetic */ b() {
        this.a = 3;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object a(com.quizlet.data.model.C4129g0 r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.data.interactor.folderstudymaterial.a
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.data.interactor.folderstudymaterial.a r0 = (com.quizlet.data.interactor.folderstudymaterial.a) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.interactor.folderstudymaterial.a r0 = new com.quizlet.data.interactor.folderstudymaterial.a
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r6)
            kotlin.r r6 = (kotlin.r) r6
            java.lang.Object r5 = r6.a
            goto L43
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            java.util.List r5 = kotlin.collections.A.b(r5)
            r0.l = r3
            java.lang.Object r5 = r4.c(r5, r0)
            if (r5 != r1) goto L43
            return r1
        L43:
            kotlin.p r6 = kotlin.r.b
            boolean r6 = r5 instanceof kotlin.q
            if (r6 != 0) goto L59
            java.util.List r5 = (java.util.List) r5     // Catch: java.lang.Throwable -> L52
            java.lang.Object r5 = kotlin.collections.CollectionsKt.L(r5)     // Catch: java.lang.Throwable -> L52
            com.quizlet.data.model.CreatedFolderStudyMaterial r5 = (com.quizlet.data.model.CreatedFolderStudyMaterial) r5     // Catch: java.lang.Throwable -> L52
            return r5
        L52:
            r5 = move-exception
            kotlin.p r6 = kotlin.r.b
            kotlin.q r5 = androidx.glance.appwidget.protobuf.Z.b(r5)
        L59:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.crashlytics.internal.settings.b.a(com.quizlet.data.model.g0, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        Object aVar;
        switch (this.a) {
            case 5:
                Throwable e = (Throwable) obj;
                Intrinsics.checkNotNullParameter(e, "e");
                AbstractC3762x6.b((org.slf4j.b) this.b, e, "Error saving MyExplanationsItem to remote");
                Objects.requireNonNull(e, "throwable is null");
                return new io.reactivex.rxjava3.internal.operators.completable.c(e, 3);
            case 13:
                Throwable e2 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(e2, "e");
                ((org.slf4j.b) ((com.quizlet.data.repository.folderset.c) this.b).d).j("Error getting FolderSets", e2);
                return E.a;
            case 14:
                Throwable e3 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(e3, "e");
                ((org.slf4j.b) ((e) this.b).e).j("no cached objects", e3);
                return E.a;
            case 15:
                Throwable e4 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(e4, "e");
                ((org.slf4j.b) ((g) this.b).f).h("Classes not found in database", e4);
                return E.a;
            case 16:
                Throwable e5 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(e5, "e");
                ((org.slf4j.b) ((com.quizlet.data.repository.user.e) this.b).d).j("no network connection", e5);
                return E.a;
            case 20:
                K p0 = (K) obj;
                Intrinsics.checkNotNullParameter(p0, "p0");
                ((N) this.b).getClass();
                ApiThreeWrapper apiThreeWrapper = (ApiThreeWrapper) p0.b;
                List responses = apiThreeWrapper != null ? apiThreeWrapper.getResponses() : null;
                if (responses == null || responses.size() < 1) {
                    throw new IllegalStateException("No content");
                }
                ModelWrapper modelWrapper = ((ApiResponse) responses.get(0)).getModelWrapper();
                Intrinsics.checkNotNullExpressionValue(modelWrapper, "getModelWrapper(...)");
                return modelWrapper;
            case 21:
                com.quizlet.features.setpage.state.d state = (com.quizlet.features.setpage.state.d) obj;
                Intrinsics.checkNotNullParameter(state, "state");
                com.quizlet.shared.usecase.srs.a mapper = (com.quizlet.shared.usecase.srs.a) ((C0138o) this.b).c;
                Intrinsics.checkNotNullParameter(state, "<this>");
                Intrinsics.checkNotNullParameter(mapper, "mapper");
                if (state instanceof com.quizlet.features.setpage.state.b) {
                    return com.quizlet.features.setpage.state.b.a;
                }
                if (state instanceof com.quizlet.features.setpage.state.c) {
                    Z1 data = (Z1) ((com.quizlet.features.setpage.state.c) state).a;
                    Intrinsics.checkNotNullParameter(data, "data");
                    DBStudySet dBStudySetB = com.quizlet.local.ormlite.models.set.a.b(data.a);
                    User user = data.b;
                    dBStudySetB.setCreator(user != null ? assistantMode.utils.studiableMetadata.b.P(user) : null);
                    aVar = new com.quizlet.features.setpage.state.c(dBStudySetB);
                } else {
                    if (!(state instanceof com.quizlet.features.setpage.state.a)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    aVar = new com.quizlet.features.setpage.state.a(((com.quizlet.features.setpage.state.a) state).a);
                }
                return aVar;
            case EventType.CDN /* 26 */:
                List groupSetsWithRecycledLocalIds = (List) obj;
                Intrinsics.checkNotNullParameter(groupSetsWithRecycledLocalIds, "groupSetsWithRecycledLocalIds");
                return ((ModelIdentityProvider) this.b).generateLocalIdsIfNeededAsync(groupSetsWithRecycledLocalIds);
            case 27:
                List userIds = (List) obj;
                Intrinsics.checkNotNullParameter(userIds, "userIds");
                return ((com.quizlet.local.ormlite.models.bookmark.a) ((com.quizlet.local.ormlite.models.bookmark.a) this.b).c).b(userIds);
            case 28:
                List it2 = (List) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                com.quizlet.data.repository.activitycenter.b bVar = (com.quizlet.data.repository.activitycenter.b) this.b;
                io.reactivex.rxjava3.internal.operators.single.g gVarG = ((com.quizlet.local.ormlite.models.studysetwithcreator.a) bVar.c).c(com.quizlet.data.repository.activitycenter.b.a(bVar, it2, true)).g(new n(it2, 2));
                Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
                return gVarG;
            default:
                List modelsWithIds = (List) obj;
                Intrinsics.checkNotNullParameter(modelsWithIds, "modelsWithIds");
                com.quizlet.data.repository.user.a aVar2 = (com.quizlet.data.repository.user.a) this.b;
                return new m(((com.quizlet.local.ormlite.database.dao.b) aVar2.d).f(modelsWithIds), null, Boolean.TRUE, 0).g(new com.quizlet.infra.legacysyncengine.features.properties.e(modelsWithIds, aVar2));
        }
    }

    @Override // com.quizlet.uicommon.ui.common.widgets.h
    public void b(i checkedSegment) {
        Intrinsics.checkNotNullParameter(checkedSegment, "checkedSegment");
        boolean z = checkedSegment == i.c;
        com.quizlet.features.setpage.viewmodel.selectedtermsmode.b bVar = (com.quizlet.features.setpage.viewmodel.selectedtermsmode.b) ((SelectedTermsModeFragment) this.b).j.getValue();
        v vVar = bVar.e;
        vVar.getClass();
        G1 g1 = G1.SET;
        z zVar = (z) vVar.b;
        long j = bVar.f;
        zVar.c(j, g1, z);
        com.quizlet.data.repository.explanations.textbook.a aVar = (com.quizlet.data.repository.explanations.textbook.a) vVar.c;
        w wVarA = ((com.quizlet.infra.legacysyncengine.datasources.factory.b) aVar.a).a(j);
        wVarA.e((com.quizlet.infra.legacysyncengine.datasources.factory.a) aVar.d);
        if (wVarA.f == z) {
            return;
        }
        wVarA.f = z;
        wVarA.c();
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object c(java.util.List r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.data.interactor.folderstudymaterial.b
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.data.interactor.folderstudymaterial.b r0 = (com.quizlet.data.interactor.folderstudymaterial.b) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.interactor.folderstudymaterial.b r0 = new com.quizlet.data.interactor.folderstudymaterial.b
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r6)
            kotlin.r r6 = (kotlin.r) r6
            java.lang.Object r5 = r6.a
            return r5
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.l = r3
            java.lang.Object r6 = r4.b
            com.onetrust.otpublishers.headless.UI.fragment.q r6 = (com.onetrust.otpublishers.headless.UI.fragment.q) r6
            java.lang.Object r5 = r6.b(r5, r0)
            if (r5 != r1) goto L43
            return r1
        L43:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.crashlytics.internal.settings.b.c(java.util.List, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public Object d(kotlin.coroutines.h hVar) {
        androidx.work.impl.model.c cVar = (androidx.work.impl.model.c) this.b;
        io.reactivex.rxjava3.internal.operators.single.g gVarB = com.google.android.gms.dynamite.d.b(com.google.android.gms.dynamite.d.e(cVar.r()), cVar.q());
        io.reactivex.rxjava3.internal.operators.single.g gVarG = cVar.o(new C4566c0(22), 0).g(new com.quizlet.data.interactor.course.a(this, 10));
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        return I1.b(com.google.android.gms.dynamite.d.b(com.google.android.gms.dynamite.d.b(gVarB, gVarG), cVar.o(new com.quizlet.quizletandroid.config.features.properties.d(4), Boolean.FALSE)), hVar);
    }

    public com.quizlet.qutils.language.e e(com.quizlet.features.infra.basestudy.manager.f studyModeManager) {
        com.quizlet.quizletandroid.util.f fVar = (com.quizlet.quizletandroid.util.f) this.b;
        Intrinsics.checkNotNullParameter(studyModeManager, "studyModeManager");
        try {
            String wordLang = studyModeManager.x.f.getWordLang();
            String defLang = studyModeManager.x.f.getDefLang();
            Intrinsics.d(wordLang);
            Intrinsics.d(defLang);
            return fVar.e(wordLang, defLang);
        } catch (Exception unused) {
            return fVar.e("??", "??");
        }
    }

    @Override // com.quizlet.local.ormlite.database.b
    public io.reactivex.rxjava3.internal.operators.completable.c f(List models) {
        Intrinsics.checkNotNullParameter(models, "models");
        Object value = ((u) this.b).getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        return com.quizlet.local.ormlite.util.b.a((Dao) value, models);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0015  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object g(java.lang.String r13, java.lang.String r14, java.lang.String r15, java.lang.String r16, kotlin.coroutines.jvm.internal.c r17) throws java.lang.Throwable {
        /*
            r12 = this;
            r0 = r17
            boolean r1 = r0 instanceof com.quizlet.data.interactor.school.c
            if (r1 == 0) goto L15
            r1 = r0
            com.quizlet.data.interactor.school.c r1 = (com.quizlet.data.interactor.school.c) r1
            int r2 = r1.l
            r3 = -2147483648(0xffffffff80000000, float:-0.0)
            r4 = r2 & r3
            if (r4 == 0) goto L15
            int r2 = r2 - r3
            r1.l = r2
            goto L1a
        L15:
            com.quizlet.data.interactor.school.c r1 = new com.quizlet.data.interactor.school.c
            r1.<init>(r12, r0)
        L1a:
            java.lang.Object r0 = r1.j
            kotlin.coroutines.intrinsics.a r2 = kotlin.coroutines.intrinsics.a.a
            int r3 = r1.l
            r4 = 1
            if (r3 == 0) goto L31
            if (r3 != r4) goto L29
            androidx.glance.appwidget.protobuf.Z.e(r0)     // Catch: java.lang.Exception -> L54
            goto L51
        L29:
            java.lang.IllegalStateException r13 = new java.lang.IllegalStateException
            java.lang.String r14 = "call to 'resume' before 'invoke' with coroutine"
            r13.<init>(r14)
            throw r13
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r0)
            java.lang.Object r0 = r12.b     // Catch: java.lang.Exception -> L54
            r10 = r0
            com.quizlet.data.repository.set.f r10 = (com.quizlet.data.repository.set.f) r10     // Catch: java.lang.Exception -> L54
            r1.l = r4     // Catch: java.lang.Exception -> L54
            com.quizlet.remote.model.school.c r5 = new com.quizlet.remote.model.school.c     // Catch: java.lang.Exception -> L54
            r11 = 0
            r6 = r13
            r7 = r14
            r8 = r15
            r9 = r16
            r5.<init>(r6, r7, r8, r9, r10, r11)     // Catch: java.lang.Exception -> L54
            java.lang.Object r13 = r10.d     // Catch: java.lang.Exception -> L54
            kotlinx.coroutines.y r13 = (kotlinx.coroutines.AbstractC5040y) r13     // Catch: java.lang.Exception -> L54
            java.lang.Object r0 = kotlinx.coroutines.E.J(r13, r5, r1)     // Catch: java.lang.Exception -> L54
            if (r0 != r2) goto L51
            return r2
        L51:
            com.quizlet.data.model.School r0 = (com.quizlet.data.model.School) r0     // Catch: java.lang.Exception -> L54
            return r0
        L54:
            com.quizlet.data.repository.school.exceptions.CreateNewSchoolException r13 = new com.quizlet.data.repository.school.exceptions.CreateNewSchoolException
            r13.<init>()
            throw r13
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.crashlytics.internal.settings.b.g(java.lang.String, java.lang.String, java.lang.String, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // com.quizlet.api.model.ISkuDetails
    public long getPriceAmountMicros() {
        return ((com.quizlet.data.model.billing.a) this.b).b;
    }

    @Override // com.quizlet.api.model.ISkuDetails
    public String getPriceCurrencyCode() {
        return ((com.quizlet.data.model.billing.a) this.b).c;
    }

    public Object h(kotlin.coroutines.jvm.internal.c cVar) {
        return ((com.quizlet.data.repository.activitycenter.b) this.b).j(I0.MAGIC_NOTES, cVar);
    }

    public a i(JSONObject jSONObject) {
        c dVar;
        int i = jSONObject.getInt("settings_version");
        if (i != 3) {
            Log.e("FirebaseCrashlytics", "Could not determine SettingsJsonTransform for settings version " + i + ". Using default settings values.", null);
            dVar = new com.quizlet.shared.usecase.folderstudymaterials.c(18);
        } else {
            dVar = new com.quizlet.shared.usecase.folderstudymaterials.d(18);
        }
        return dVar.a((com.onetrust.otpublishers.headless.Internal.Helper.h) this.b, jSONObject);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object j(kotlin.coroutines.jvm.internal.c r6) {
        /*
            r5 = this;
            boolean r0 = r6 instanceof com.quizlet.local.datastore.preferences.t0
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.local.datastore.preferences.t0 r0 = (com.quizlet.local.datastore.preferences.t0) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.local.datastore.preferences.t0 r0 = new com.quizlet.local.datastore.preferences.t0
            r0.<init>(r5, r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.datastore.preferences.core.f r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L50
        L29:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            java.lang.String r6 = "should_get_free_trial"
            androidx.datastore.preferences.core.f r6 = com.google.android.gms.internal.mlkit_vision_barcode.R6.a(r6)
            java.lang.Object r2 = r5.b
            androidx.datastore.core.h r2 = (androidx.datastore.core.InterfaceC1076h) r2
            kotlinx.coroutines.flow.i r2 = r2.getData()
            r0.j = r6
            r0.m = r3
            java.lang.Object r0 = kotlinx.coroutines.flow.e0.p(r2, r0)
            if (r0 != r1) goto L4d
            return r1
        L4d:
            r4 = r0
            r0 = r6
            r6 = r4
        L50:
            androidx.datastore.preferences.core.b r6 = (androidx.datastore.preferences.core.b) r6
            java.lang.Object r6 = r6.c(r0)
            java.lang.Boolean r0 = java.lang.Boolean.TRUE
            boolean r6 = kotlin.jvm.internal.Intrinsics.b(r6, r0)
            java.lang.Boolean r6 = java.lang.Boolean.valueOf(r6)
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.crashlytics.internal.settings.b.j(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object k(kotlin.coroutines.jvm.internal.c r6) {
        /*
            r5 = this;
            boolean r0 = r6 instanceof com.quizlet.local.datastore.preferences.u0
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.local.datastore.preferences.u0 r0 = (com.quizlet.local.datastore.preferences.u0) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.local.datastore.preferences.u0 r0 = new com.quizlet.local.datastore.preferences.u0
            r0.<init>(r5, r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.datastore.preferences.core.f r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L50
        L29:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            java.lang.String r6 = "should_show_free_trial_success"
            androidx.datastore.preferences.core.f r6 = com.google.android.gms.internal.mlkit_vision_barcode.R6.a(r6)
            java.lang.Object r2 = r5.b
            androidx.datastore.core.h r2 = (androidx.datastore.core.InterfaceC1076h) r2
            kotlinx.coroutines.flow.i r2 = r2.getData()
            r0.j = r6
            r0.m = r3
            java.lang.Object r0 = kotlinx.coroutines.flow.e0.p(r2, r0)
            if (r0 != r1) goto L4d
            return r1
        L4d:
            r4 = r0
            r0 = r6
            r6 = r4
        L50:
            androidx.datastore.preferences.core.b r6 = (androidx.datastore.preferences.core.b) r6
            java.lang.Object r6 = r6.c(r0)
            java.lang.Boolean r0 = java.lang.Boolean.TRUE
            boolean r6 = kotlin.jvm.internal.Intrinsics.b(r6, r0)
            java.lang.Boolean r6 = java.lang.Boolean.valueOf(r6)
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.crashlytics.internal.settings.b.k(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public Uri l(Uri uri, String str) throws IOException {
        String scheme;
        if (uri == null || (scheme = uri.getScheme()) == null) {
            return null;
        }
        Context context = (Context) this.b;
        File file = new File(context.getCacheDir(), "mlkit_docscan_ui_client");
        if (!file.exists()) {
            file.mkdir();
        }
        File file2 = new File(file, SystemClock.elapsedRealtimeNanos() + str);
        try {
            InputStream inputStreamA = AbstractC3728t4.a(context, uri, (Objects.equals(context.getPackageName(), "com.google.android.gms") || !scheme.equals("content")) ? T3.d : T3.c);
            try {
                FileOutputStream fileOutputStream = new FileOutputStream(file2);
                try {
                    byte[] bArr = new byte[1024];
                    while (true) {
                        int i = inputStreamA.read(bArr);
                        if (i == -1) {
                            fileOutputStream.flush();
                            Uri uriFromFile = Uri.fromFile(file2);
                            fileOutputStream.close();
                            inputStreamA.close();
                            return uriFromFile;
                        }
                        fileOutputStream.write(bArr, 0, i);
                    }
                } finally {
                }
            } finally {
            }
        } catch (IOException e) {
            String strConcat = "Failed to save file to local: ".concat(uri.toString());
            if (!Log.isLoggable("ResultHelper", 6)) {
                return null;
            }
            Log.e("ResultHelper", strConcat, e);
            return null;
        }
    }

    public void m(String str) {
        if (str == null) {
            return;
        }
        try {
            com.google.mlkit.vision.documentscanner.internal.d dVar = new com.google.mlkit.vision.documentscanner.internal.d((Context) this.b);
            k kVarA = AbstractC2027eu.a();
            kVarA.e = new Feature[]{com.google.mlkit.common.sdkinternal.h.c};
            kVarA.d = new androidx.sqlite.db.a(str, 2);
            kVarA.b = 24337;
            S3.e(dVar.c(0, kVarA.a()));
        } catch (InterruptedException | ExecutionException e) {
            if (Log.isLoggable("ResultHelper", 6)) {
                Log.e("ResultHelper", "Failed to cleanup GMS Core cache", e);
            }
        }
    }

    public /* synthetic */ b(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    public b(l questionRemoteDataStore) {
        this.a = 12;
        Intrinsics.checkNotNullParameter(questionRemoteDataStore, "questionRemoteDataStore");
        this.b = questionRemoteDataStore;
    }

    public b(v getUsersClassMembershipsUseCase) {
        this.a = 23;
        Intrinsics.checkNotNullParameter(getUsersClassMembershipsUseCase, "getUsersClassMembershipsUseCase");
        this.b = getUsersClassMembershipsUseCase;
    }

    public b(C3 practiceTestsRepository) {
        this.a = 9;
        Intrinsics.checkNotNullParameter(practiceTestsRepository, "practiceTestsRepository");
        this.b = practiceTestsRepository;
    }

    public b(com.quizlet.data.repository.activitycenter.b checkUserFeatureEligibilityUseCase) {
        this.a = 8;
        Intrinsics.checkNotNullParameter(checkUserFeatureEligibilityUseCase, "checkUserFeatureEligibilityUseCase");
        this.b = checkUserFeatureEligibilityUseCase;
    }

    public b(com.quizlet.remote.model.notes.e repository) {
        this.a = 11;
        Intrinsics.checkNotNullParameter(repository, "repository");
        this.b = repository;
    }

    public b(q addFolderStudyMaterialRepository) {
        this.a = 7;
        Intrinsics.checkNotNullParameter(addFolderStudyMaterialRepository, "addFolderStudyMaterialRepository");
        this.b = addFolderStudyMaterialRepository;
    }

    public b(androidx.work.impl.model.n repository) {
        this.a = 6;
        Intrinsics.checkNotNullParameter(repository, "repository");
        this.b = repository;
    }

    public b(com.quizlet.data.model.billing.a skuDetails) {
        this.a = 4;
        Intrinsics.checkNotNullParameter(skuDetails, "skuDetails");
        this.b = skuDetails;
    }

    public b(com.quizlet.quizletandroid.util.f languageUtil) {
        this.a = 19;
        Intrinsics.checkNotNullParameter(languageUtil, "languageUtil");
        this.b = languageUtil;
    }

    public b(com.quizlet.data.repository.set.f repository) {
        this.a = 10;
        Intrinsics.checkNotNullParameter(repository, "repository");
        this.b = repository;
    }

    public b(DatabaseHelper database) {
        this.a = 25;
        Intrinsics.checkNotNullParameter(database, "database");
        this.b = kotlin.l.b(new com.quizlet.local.ormlite.database.dao.a(database, 5));
    }

    public b(androidx.work.impl.model.c userProperties) {
        this.a = 18;
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
        this.b = userProperties;
    }

    public b(com.quizlet.qutils.image.loading.a imageLoader) {
        this.a = 17;
        Intrinsics.checkNotNullParameter(imageLoader, "imageLoader");
        this.b = imageLoader;
    }

    public b(InterfaceC1076h dataStore) {
        this.a = 24;
        Intrinsics.checkNotNullParameter(dataStore, "dataStore");
        this.b = dataStore;
    }
}

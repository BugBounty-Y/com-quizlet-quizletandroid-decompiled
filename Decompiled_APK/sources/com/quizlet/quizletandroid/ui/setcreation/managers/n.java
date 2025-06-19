package com.quizlet.quizletandroid.ui.setcreation.managers;

import android.graphics.Bitmap;
import android.view.View;
import com.google.android.gms.internal.ads.Zh;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.google.android.gms.measurement.internal.J;
import com.quizlet.api.model.Bounds;
import com.quizlet.api.model.ImageAnalysisResponse;
import com.quizlet.api.model.ImageAnalysisResponseData;
import com.quizlet.api.model.Point;
import com.quizlet.api.model.TextAnnotations;
import com.quizlet.data.model.AbstractC4119d0;
import com.quizlet.data.model.C4116c1;
import com.quizlet.data.model.C4132h0;
import com.quizlet.data.model.Q;
import com.quizlet.data.model.User;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.persisted.DBGroup;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.generated.enums.w1;
import com.quizlet.quizletandroid.ui.setpage.addset.LoggedInUserClassSelectionListFragment;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.C4723t;
import com.quizlet.remote.model.folder.RemoteFolder;
import com.quizlet.remote.model.user.RemoteUser;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.concurrent.TimeUnit;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.collections.G;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.I;
import retrofit2.K;

/* loaded from: classes3.dex */
public final class n implements io.reactivex.rxjava3.functions.h, com.quizlet.features.infra.legacyadapter.d, com.quizlet.richtext.rendering.b, com.quizlet.remote.mapper.base.b, io.reactivex.rxjava3.core.h {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ n(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // io.reactivex.rxjava3.core.h
    public void a(io.reactivex.rxjava3.disposables.b bVar) {
        io.reactivex.rxjava3.internal.disposables.a.e((io.reactivex.rxjava3.internal.operators.completable.l) this.b, bVar);
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        com.quizlet.scandocument.model.d dVar;
        Object obj2 = this.b;
        switch (this.a) {
            case 0:
                DBStudySet studySet = (DBStudySet) obj;
                Intrinsics.checkNotNullParameter(studySet, "it");
                Zh zh = (Zh) obj2;
                zh.getClass();
                Intrinsics.checkNotNullParameter(studySet, "studySet");
                if (studySet.getId() <= 0 || !studySet.getIsCreated()) {
                    long seconds = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis());
                    if (studySet.getId() <= 0) {
                        studySet.setReadyToCreate(true);
                    } else {
                        studySet.setPublishedTimestamp(Long.valueOf(seconds));
                    }
                    studySet.setTimestamp((int) seconds);
                    ((com.quizlet.infra.legacysyncengine.managers.i) zh.f).c(studySet);
                }
                return studySet;
            case 2:
                List recommendedSetsList = (List) obj;
                Intrinsics.checkNotNullParameter(recommendedSetsList, "recommendedSetsList");
                List<C4723t> listP0 = CollectionsKt.p0(recommendedSetsList, 3);
                ArrayList arrayList = new ArrayList();
                for (C4723t c4723t : listP0) {
                    w1 w1Var = w1.EDU_REC;
                    ((androidx.work.impl.model.e) obj2).getClass();
                    G.u(arrayList, androidx.work.impl.model.e.w(c4723t, w1Var));
                }
                return arrayList;
            case 7:
                List it2 = (List) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                Object objFirstOrNull = CollectionsKt.firstOrNull(T.f((com.quizlet.remote.model.progress.a) ((com.quizlet.remote.model.progress.e) obj2).b, it2));
                return objFirstOrNull == null ? Q.a : new C4116c1(objFirstOrNull);
            default:
                K response = (K) obj;
                Intrinsics.checkNotNullParameter(response, "response");
                ImageAnalysisResponse imageAnalysisResponse = (ImageAnalysisResponse) response.b;
                if (imageAnalysisResponse == null || imageAnalysisResponse.getResponses().isEmpty()) {
                    I i = response.c;
                    return io.reactivex.rxjava3.core.i.k(new NullPointerException(i != null ? i.f() : null));
                }
                ImageAnalysisResponseData response2 = (ImageAnalysisResponseData) CollectionsKt.L(imageAnalysisResponse.getResponses());
                Intrinsics.checkNotNullParameter(response2, "response");
                List<TextAnnotations> textAnnotations = response2.getData().getImageAnalysis().getTextAnnotations();
                if (textAnnotations.isEmpty()) {
                    dVar = new com.quizlet.scandocument.model.d("", kotlin.collections.K.a);
                } else {
                    List<TextAnnotations> listSubList = textAnnotations.subList(1, textAnnotations.size());
                    ArrayList arrayList2 = new ArrayList(C.q(listSubList, 10));
                    for (TextAnnotations textAnnotations2 : listSubList) {
                        String description = textAnnotations2.getDescription();
                        Bounds boundingPoly = textAnnotations2.getBoundingPoly();
                        Intrinsics.checkNotNullParameter(boundingPoly, "<this>");
                        List<Point> vertices = boundingPoly.getVertices();
                        ArrayList arrayList3 = new ArrayList(C.q(vertices, 10));
                        for (Point point : vertices) {
                            arrayList3.add(new com.quizlet.scandocument.model.i(point.getX(), point.getY()));
                        }
                        arrayList2.add(new com.quizlet.scandocument.model.c(description, new com.quizlet.scandocument.model.j(arrayList3)));
                    }
                    String locale = ((TextAnnotations) CollectionsKt.L(textAnnotations)).getLocale();
                    dVar = new com.quizlet.scandocument.model.d(locale != null ? locale : "", arrayList2);
                }
                return io.reactivex.rxjava3.core.i.p(new com.quizlet.scandocument.model.h((Bitmap) obj2, dVar));
        }
    }

    @Override // com.quizlet.features.infra.legacyadapter.d
    public boolean b(View childView, int i, DBModel dBModel) {
        Intrinsics.checkNotNullParameter(childView, "childView");
        return false;
    }

    @Override // com.quizlet.features.infra.legacyadapter.d
    public boolean d(View childView, int i, DBModel dBModel) {
        DBGroup dBGroup = (DBGroup) dBModel;
        Intrinsics.checkNotNullParameter(childView, "childView");
        if (dBGroup == null) {
            return false;
        }
        long id = dBGroup.getId();
        String str = LoggedInUserClassSelectionListFragment.F;
        LoggedInUserClassSelectionListFragment loggedInUserClassSelectionListFragment = (LoggedInUserClassSelectionListFragment) this.b;
        loggedInUserClassSelectionListFragment.t.notifyDataSetChanged();
        ((com.quizlet.quizletandroid.ui.setpage.addset.c) loggedInUserClassSelectionListFragment.A.getValue()).e.b(id);
        return true;
    }

    @Override // com.quizlet.remote.mapper.base.a
    public List e(List list) {
        return T.f(this, list);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object f(com.quizlet.features.infra.basestudy.manager.f r8, kotlin.coroutines.jvm.internal.c r9) {
        /*
            r7 = this;
            boolean r0 = r9 instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.settings.interaction.b
            if (r0 == 0) goto L13
            r0 = r9
            com.quizlet.quizletandroid.ui.studymodes.assistant.settings.interaction.b r0 = (com.quizlet.quizletandroid.ui.studymodes.assistant.settings.interaction.b) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.quizletandroid.ui.studymodes.assistant.settings.interaction.b r0 = new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.interaction.b
            r0.<init>(r7, r9)
        L18:
            java.lang.Object r9 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            boolean r8 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L60
        L29:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            com.quizlet.features.infra.studysetting.managers.a r9 = r8.g()
            r9.getClass()
            com.quizlet.generated.enums.E1 r2 = com.quizlet.generated.enums.E1.GUIDANCE_DISABLED
            boolean r2 = com.quizlet.features.infra.studysetting.managers.a.d(r9, r2)
            if (r2 == 0) goto L46
            java.lang.Boolean r8 = java.lang.Boolean.FALSE
            return r8
        L46:
            com.quizlet.generated.enums.E1 r2 = com.quizlet.generated.enums.E1.TASKS_ENABLED
            boolean r9 = com.quizlet.features.infra.studysetting.managers.a.d(r9, r2)
            r0.j = r9
            r0.m = r3
            java.lang.Object r2 = r7.b
            com.google.android.gms.measurement.internal.J r2 = (com.google.android.gms.measurement.internal.J) r2
            long r4 = r8.u
            java.lang.Enum r8 = r2.e(r4, r0)
            if (r8 != r1) goto L5d
            return r1
        L5d:
            r6 = r9
            r9 = r8
            r8 = r6
        L60:
            com.quizlet.featuregate.features.studymodes.learn.b r9 = (com.quizlet.featuregate.features.studymodes.learn.b) r9
            com.quizlet.featuregate.features.studymodes.learn.b r0 = com.quizlet.featuregate.features.studymodes.learn.b.b
            if (r9 != r0) goto L69
            if (r8 == 0) goto L69
            goto L6a
        L69:
            r3 = 0
        L6a:
            java.lang.Boolean r8 = java.lang.Boolean.valueOf(r3)
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.setcreation.managers.n.f(com.quizlet.features.infra.basestudy.manager.f, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // com.quizlet.remote.mapper.base.a
    /* renamed from: g, reason: merged with bridge method [inline-methods] */
    public C4132h0 c(com.quizlet.remote.model.union.folderwithcreator.f remote) {
        Intrinsics.checkNotNullParameter(remote, "remote");
        AbstractC4119d0 abstractC4119d0G = ((com.quizlet.quizletandroid.ui.folder.logging.a) this.b).g(remote.a);
        RemoteUser remoteUser = remote.b;
        return new C4132h0(abstractC4119d0G, remoteUser != null ? com.quizlet.quizletandroid.ui.activitycenter.models.a.b(remoteUser) : null);
    }

    @Override // com.quizlet.remote.mapper.base.c
    public Object h(Object obj) {
        C4132h0 data = (C4132h0) obj;
        Intrinsics.checkNotNullParameter(data, "data");
        RemoteFolder remoteFolderJ = com.quizlet.quizletandroid.ui.folder.logging.a.j(data.a);
        User user = data.b;
        return new com.quizlet.remote.model.union.folderwithcreator.f(remoteFolderJ, user != null ? com.quizlet.quizletandroid.ui.activitycenter.models.a.d(user) : null);
    }

    public void i(com.quizlet.quizletandroid.ui.login.di.a definition) {
        Intrinsics.checkNotNullParameter(definition, "definition");
        android.support.v4.media.session.a.A(((io.ktor.util.collections.a) this.b).a(definition));
    }

    @Override // io.reactivex.rxjava3.core.h
    public void onComplete() {
        ((io.reactivex.rxjava3.core.h) ((io.reactivex.rxjava3.internal.operators.completable.l) this.b).b).onComplete();
    }

    @Override // io.reactivex.rxjava3.core.h
    public void onError(Throwable th) {
        ((io.reactivex.rxjava3.core.h) ((io.reactivex.rxjava3.internal.operators.completable.l) this.b).b).onError(th);
    }

    @Override // io.reactivex.rxjava3.core.h, io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        ((io.reactivex.rxjava3.core.h) ((io.reactivex.rxjava3.internal.operators.completable.l) this.b).b).onSuccess(obj);
    }

    public n(J getLearnTaskVariantUseCase) {
        this.a = 3;
        Intrinsics.checkNotNullParameter(getLearnTaskVariantUseCase, "getLearnTaskVariantUseCase");
        this.b = getLearnTaskVariantUseCase;
    }

    public n(com.quizlet.quizletandroid.ui.activitycenter.models.a userMapper, com.quizlet.quizletandroid.ui.folder.logging.a folderMapper) {
        this.a = 8;
        Intrinsics.checkNotNullParameter(folderMapper, "folderMapper");
        Intrinsics.checkNotNullParameter(userMapper, "userMapper");
        this.b = folderMapper;
    }

    public n(com.quizlet.data.repository.set.f nightThemeManager) {
        this.a = 4;
        Intrinsics.checkNotNullParameter(nightThemeManager, "nightThemeManager");
        this.b = nightThemeManager;
    }

    public n(int i) {
        this.a = i;
        switch (i) {
            case 12:
                this.b = new LinkedHashSet();
                break;
            default:
                this.b = new io.ktor.util.collections.a();
                break;
        }
    }

    public n(com.quizlet.remote.service.h service, com.quizlet.quizletandroid.ui.onboarding.a membershipMapper) {
        this.a = 5;
        Intrinsics.checkNotNullParameter(service, "service");
        Intrinsics.checkNotNullParameter(membershipMapper, "membershipMapper");
        this.b = service;
    }

    public n(com.quizlet.remote.service.n service) {
        this.a = 6;
        Intrinsics.checkNotNullParameter(service, "service");
        this.b = service;
    }
}

package com.braze;

import com.braze.managers.a0;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_camera.L1;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3537t4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3762x6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3770y6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3771z;
import com.j256.ormlite.dao.Dao;
import com.quizlet.db.data.models.base.AssociationNames;
import com.quizlet.quizletandroid.ui.common.ads.C4636c;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.user.UserResponse;
import com.quizlet.remote.service.InterfaceC4776c;
import com.quizlet.remote.service.InterfaceC4777d;
import io.reactivex.rxjava3.internal.operators.observable.C4905y;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.braze.p, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C1510p implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;
    public final /* synthetic */ Object c;

    public /* synthetic */ C1510p(Object obj, long j, int i) {
        this.a = i;
        this.c = obj;
        this.b = j;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        io.reactivex.rxjava3.core.i j;
        io.reactivex.rxjava3.core.i iVarG;
        switch (this.a) {
            case 0:
                return Braze.schedulePushDelivery$lambda$203((Braze) this.c, this.b);
            case 1:
                return a0.a((a0) this.c, this.b);
            case 2:
                return com.braze.storage.y.a((Map.Entry) this.c, this.b);
            case 3:
                return com.braze.triggers.managers.g.a((com.braze.triggers.actions.a) this.c, this.b);
            case 4:
                com.quizlet.data.repository.classfolder.e eVar = (com.quizlet.data.repository.classfolder.e) ((androidx.work.impl.model.e) this.c).b;
                com.quizlet.data.repository.explanations.myexplanations.a aVar = (com.quizlet.data.repository.explanations.myexplanations.a) eVar.b;
                com.quizlet.data.repository.widget.b bVar = (com.quizlet.data.repository.widget.b) aVar.c;
                long j2 = this.b;
                List classIds = kotlin.collections.A.b(Long.valueOf(j2));
                Intrinsics.checkNotNullParameter(classIds, "classIds");
                com.quizlet.login.authentication.login.a aVar2 = (com.quizlet.login.authentication.login.a) bVar.b;
                Intrinsics.checkNotNullParameter(classIds, "classIds");
                io.reactivex.rxjava3.internal.operators.single.g gVarG = ((InterfaceC4776c) aVar2.b).a(com.google.android.gms.internal.mlkit_vision_barcode.U.c(classIds), null).g(new com.quizlet.remote.model.classfolder.a(bVar, null));
                Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
                io.reactivex.rxjava3.core.i iVarM = ((com.quizlet.local.ormlite.models.bookmark.a) aVar.b).c(j2).m();
                Intrinsics.checkNotNullExpressionValue(iVarM, "toObservable(...)");
                io.reactivex.rxjava3.internal.operators.observable.J j3 = new io.reactivex.rxjava3.internal.operators.observable.J(new com.jakewharton.rxbinding4.a(new com.quizlet.data.repository.classfolder.b(0, eVar, gVarG), 4), new com.google.mlkit.vision.documentscanner.internal.c(eVar, 10), 4);
                Intrinsics.checkNotNullExpressionValue(j3, "onErrorResumeNext(...)");
                io.reactivex.rxjava3.internal.operators.observable.J jQ = io.reactivex.rxjava3.core.i.g(iVarM, j3).q(com.quizlet.data.repository.classfolder.d.a);
                Intrinsics.checkNotNullExpressionValue(jQ, "map(...)");
                return jQ;
            case 5:
                return ((com.quizlet.data.repository.folderwithcreator.e) ((com.quizlet.data.interactor.folderwithcreator.m) this.c).a).f(this.b);
            case 6:
                com.quizlet.data.repository.folderwithcreator.e eVar2 = (com.quizlet.data.repository.folderwithcreator.e) this.c;
                com.quizlet.data.repository.folderwithcreatorinclass.e eVar3 = (com.quizlet.data.repository.folderwithcreatorinclass.e) eVar2.b;
                androidx.work.impl.model.c cVar = (androidx.work.impl.model.c) ((androidx.work.impl.model.l) eVar3.a).b;
                com.quizlet.local.ormlite.models.bookmark.a aVar3 = (com.quizlet.local.ormlite.models.bookmark.a) cVar.b;
                long j4 = this.b;
                io.reactivex.rxjava3.internal.operators.single.g gVarE = aVar3.c(j4).e(new com.quizlet.data.interactor.achievements.f(cVar, 21));
                Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
                io.reactivex.rxjava3.internal.operators.observable.J j5 = new io.reactivex.rxjava3.internal.operators.observable.J(gVarE.m(), new com.google.firebase.crashlytics.internal.settings.b(eVar3, 14), 4);
                Intrinsics.checkNotNullExpressionValue(j5, "onErrorResumeNext(...)");
                io.reactivex.rxjava3.internal.operators.observable.J j6 = new io.reactivex.rxjava3.internal.operators.observable.J(new com.jakewharton.rxbinding4.a(new com.quizlet.data.repository.folderwithcreatorinclass.b(eVar3, j4, 0), 4), new com.quizlet.data.interactor.achievements.f(eVar3, 9), 4);
                Intrinsics.checkNotNullExpressionValue(j6, "onErrorResumeNext(...)");
                io.reactivex.rxjava3.internal.operators.observable.r rVarG = io.reactivex.rxjava3.core.i.g(j5, j6);
                Intrinsics.checkNotNullExpressionValue(rVarG, "concat(...)");
                io.reactivex.rxjava3.core.i iVarM2 = rVarG.m(new com.google.android.material.floatingactionbutton.c(eVar2, 8), SubsamplingScaleImageView.TILE_SIZE_AUTO);
                Intrinsics.checkNotNullExpressionValue(iVarM2, "flatMap(...)");
                return iVarM2;
            case 7:
                com.quizlet.data.repository.studysetwithcreator.d dVar = (com.quizlet.data.repository.studysetwithcreator.d) ((io.ktor.client.plugins.api.d) this.c).b;
                com.quizlet.local.ormlite.models.studysetwithcreator.a aVar4 = (com.quizlet.local.ormlite.models.studysetwithcreator.a) ((androidx.work.impl.model.v) dVar.a).b;
                long j7 = this.b;
                io.reactivex.rxjava3.internal.operators.single.g gVarG2 = aVar4.c(kotlin.collections.A.b(Long.valueOf(j7))).g(new com.google.mlkit.vision.documentscanner.internal.c(dVar, 12));
                Intrinsics.checkNotNullExpressionValue(gVarG2, "map(...)");
                io.reactivex.rxjava3.core.i iVarM3 = gVarG2.m().m(com.quizlet.data.repository.studysetwithcreator.c.c, SubsamplingScaleImageView.TILE_SIZE_AUTO);
                Intrinsics.checkNotNullExpressionValue(iVarM3, "flatMap(...)");
                io.reactivex.rxjava3.internal.operators.observable.J j8 = new io.reactivex.rxjava3.internal.operators.observable.J(iVarM3, new com.quizlet.data.interactor.studysetwithcreator.a(dVar, 1), 4);
                Intrinsics.checkNotNullExpressionValue(j8, "onErrorResumeNext(...)");
                if (j7 < 0) {
                    j = io.reactivex.rxjava3.internal.operators.observable.E.a;
                } else {
                    j = new io.reactivex.rxjava3.internal.operators.observable.J(new com.jakewharton.rxbinding4.a(new com.quizlet.data.repository.folderwithcreatorinclass.b(dVar, j7, 1), 4), new com.lyft.android.scissors.b(dVar, 12), 4);
                    Intrinsics.checkNotNullExpressionValue(j, "onErrorResumeNext(...)");
                }
                io.reactivex.rxjava3.internal.operators.observable.o0 o0Var = new io.reactivex.rxjava3.internal.operators.observable.o0(io.reactivex.rxjava3.core.i.g(j8, j), io.reactivex.rxjava3.core.i.k(new IOException("failed to get study set by ID")), 0);
                Intrinsics.checkNotNullExpressionValue(o0Var, "switchIfEmpty(...)");
                return o0Var;
            case 8:
                com.quizlet.data.repository.studysetwithcreatorinclass.g gVar = (com.quizlet.data.repository.studysetwithcreatorinclass.g) ((androidx.work.impl.model.c) this.c).b;
                com.quizlet.data.repository.activitycenter.b bVar2 = (com.quizlet.data.repository.activitycenter.b) ((com.quizlet.data.interactor.school.b) gVar.b).b;
                com.quizlet.local.ormlite.models.bookmark.a aVar5 = (com.quizlet.local.ormlite.models.bookmark.a) bVar2.b;
                Dao daoD = ((com.quizlet.data.interactor.course.a) aVar5.d).d();
                StringBuilder sb = new StringBuilder("\n                SELECT * FROM group_set\n                WHERE groupId = ");
                long j9 = this.b;
                sb.append(j9);
                sb.append("\n                AND isDeleted = 0\n        ");
                io.reactivex.rxjava3.internal.operators.single.g gVarE2 = AbstractC3771z.b((com.quizlet.shared.usecase.folderstudymaterials.b) aVar5.c, com.quizlet.local.ormlite.util.b.b(daoD, kotlin.text.x.c(sb.toString()))).e(new com.google.firebase.crashlytics.internal.settings.b(bVar2, 28));
                Intrinsics.checkNotNullExpressionValue(gVarE2, "flatMap(...)");
                io.reactivex.rxjava3.internal.operators.observable.J j10 = new io.reactivex.rxjava3.internal.operators.observable.J(gVarE2.m(), new com.google.firebase.crashlytics.internal.settings.b(gVar, 15), 4);
                Intrinsics.checkNotNullExpressionValue(j10, "onErrorResumeNext(...)");
                io.reactivex.rxjava3.internal.operators.observable.J j11 = new io.reactivex.rxjava3.internal.operators.observable.J(new com.jakewharton.rxbinding4.a(new com.quizlet.data.repository.folderwithcreatorinclass.b(gVar, j9, 2), 4), new com.onetrust.otpublishers.headless.UI.fragment.q(gVar, 12), 4);
                Intrinsics.checkNotNullExpressionValue(j11, "onErrorResumeNext(...)");
                io.reactivex.rxjava3.internal.operators.observable.r rVarG2 = io.reactivex.rxjava3.core.i.g(j10, j11);
                Intrinsics.checkNotNullExpressionValue(rVarG2, "concat(...)");
                return rVarG2;
            case 9:
                com.quizlet.data.repository.term.g gVar2 = (com.quizlet.data.repository.term.g) ((androidx.work.impl.model.e) this.c).b;
                io.reactivex.rxjava3.internal.operators.flowable.b bVar3 = new io.reactivex.rxjava3.internal.operators.flowable.b(new com.quizlet.data.repository.term.a(gVar2, this.b, 7), 4);
                Intrinsics.checkNotNullExpressionValue(bVar3, "defer(...)");
                return AbstractC3762x6.c(bVar3, gVar2.e, "Error retrieving terms from remote");
            case 10:
                com.quizlet.data.repository.user.a aVar6 = (com.quizlet.data.repository.user.a) ((com.quizlet.data.interactor.school.b) this.c).b;
                com.quizlet.data.repository.user.a aVar7 = (com.quizlet.data.repository.user.a) ((com.quizlet.data.repository.activitycenter.b) aVar6.b).b;
                com.quizlet.local.ormlite.database.dao.b bVar4 = (com.quizlet.local.ormlite.database.dao.b) aVar7.d;
                long j12 = this.b;
                io.reactivex.rxjava3.internal.operators.maybe.j jVar = new io.reactivex.rxjava3.internal.operators.maybe.j(AbstractC3770y6.b(bVar4.a(kotlin.collections.A.b(Long.valueOf(j12)))), new com.quizlet.shared.usecase.studiableMetadata.a((retrofit2.adapter.rxjava3.d) aVar7.c), 1);
                Intrinsics.checkNotNullExpressionValue(jVar, "map(...)");
                io.reactivex.rxjava3.internal.operators.observable.J j13 = new io.reactivex.rxjava3.internal.operators.observable.J(jVar.g(), new com.google.firebase.crashlytics.internal.common.j(aVar6, 14), 4);
                Intrinsics.checkNotNullExpressionValue(j13, "onErrorResumeNext(...)");
                io.reactivex.rxjava3.internal.operators.observable.J j14 = new io.reactivex.rxjava3.internal.operators.observable.J(new com.jakewharton.rxbinding4.a(new com.quizlet.data.repository.folderwithcreatorinclass.b(aVar6, j12, 3), 4), new com.lyft.android.scissors.b(aVar6, 13), 4);
                Intrinsics.checkNotNullExpressionValue(j14, "onErrorResumeNext(...)");
                io.reactivex.rxjava3.internal.operators.observable.r rVarG3 = io.reactivex.rxjava3.core.i.g(j13, j14);
                Intrinsics.checkNotNullExpressionValue(rVarG3, "concat(...)");
                return rVarG3;
            case 11:
                return ((com.quizlet.data.repository.user.e) ((com.quizlet.data.interactor.set.c) this.c).a).e(this.b);
            case 12:
                androidx.compose.foundation.text.input.internal.u uVar = (androidx.compose.foundation.text.input.internal.u) ((com.quizlet.data.repository.classmembership.c) this.c).a;
                io.reactivex.rxjava3.internal.operators.single.g gVarG3 = ((InterfaceC4777d) uVar.b).a(this.b, Boolean.FALSE).g(new com.quizlet.remote.model.classmembership.a(uVar));
                Intrinsics.checkNotNullExpressionValue(gVarG3, "map(...)");
                return gVarG3;
            case 13:
                com.quizlet.data.repository.folderwithcreatorinclass.e eVar4 = (com.quizlet.data.repository.folderwithcreatorinclass.e) this.c;
                com.quizlet.data.interactor.progress.c cVar2 = (com.quizlet.data.interactor.progress.c) ((androidx.work.impl.model.l) eVar4.a).c;
                com.quizlet.login.common.interactors.d dVar2 = (com.quizlet.login.common.interactors.d) cVar2.a;
                io.reactivex.rxjava3.internal.operators.single.g gVarG4 = ((InterfaceC4776c) dVar2.b).c(com.google.android.gms.internal.mlkit_vision_barcode.U.c(kotlin.collections.A.b(Long.valueOf(this.b)))).g(new com.quizlet.remote.model.union.folderwithcreatorinclass.a(cVar2));
                Intrinsics.checkNotNullExpressionValue(gVarG4, "map(...)");
                io.reactivex.rxjava3.internal.operators.single.g gVarE3 = gVarG4.e(new com.onetrust.otpublishers.headless.UI.fragment.q(eVar4, 11));
                Intrinsics.checkNotNullExpressionValue(gVarE3, "flatMap(...)");
                io.reactivex.rxjava3.internal.operators.single.g gVarG5 = gVarE3.g(com.quizlet.data.repository.folderwithcreatorinclass.d.a);
                Intrinsics.checkNotNullExpressionValue(gVarG5, "map(...)");
                return gVarG5;
            case 14:
                com.quizlet.data.repository.studysetwithcreator.d dVar3 = (com.quizlet.data.repository.studysetwithcreator.d) this.c;
                com.quizlet.remote.model.union.studysetwithcreator.c cVar3 = (com.quizlet.remote.model.union.studysetwithcreator.c) ((androidx.work.impl.model.v) dVar3.a).c;
                List setIds = kotlin.collections.A.b(Long.valueOf(this.b));
                Intrinsics.checkNotNullParameter(setIds, "studySetIds");
                com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c cVar4 = cVar3.a;
                Intrinsics.checkNotNullParameter(setIds, "setIds");
                io.reactivex.rxjava3.internal.operators.single.g gVarG6 = ((com.quizlet.remote.service.B) cVar4.b).a(com.google.android.gms.internal.mlkit_vision_barcode.U.c(setIds), kotlin.collections.B.j(AssociationNames.CREATOR, "subjectClassification_ae86c4b")).g(new com.quizlet.remote.model.union.studysetwithcreator.b());
                Intrinsics.checkNotNullExpressionValue(gVarG6, "map(...)");
                io.reactivex.rxjava3.internal.operators.single.g gVarG7 = new io.reactivex.rxjava3.internal.operators.single.d(gVarG6, new com.quizlet.analytics.marketing.e(dVar3, 2), 0).g(com.quizlet.data.repository.studysetwithcreator.c.b);
                Intrinsics.checkNotNullExpressionValue(gVarG7, "map(...)");
                return gVarG7;
            case 15:
                com.quizlet.data.repository.studysetwithcreatorinclass.g gVar3 = (com.quizlet.data.repository.studysetwithcreatorinclass.g) this.c;
                com.quizlet.remote.model.union.studysetwithcreatorinclass.e eVar5 = (com.quizlet.remote.model.union.studysetwithcreatorinclass.e) ((com.quizlet.data.interactor.school.b) gVar3.b).c;
                List classIds2 = kotlin.collections.A.b(Long.valueOf(this.b));
                Intrinsics.checkNotNullParameter(classIds2, "classIds");
                io.reactivex.rxjava3.internal.operators.single.g gVarE4 = L1.e(eVar5.d, new com.quizlet.remote.model.union.studysetwithcreatorinclass.b(eVar5, classIds2, true, null)).e(new com.google.firebase.messaging.p(gVar3, 15));
                Intrinsics.checkNotNullExpressionValue(gVarE4, "flatMap(...)");
                io.reactivex.rxjava3.internal.operators.single.g gVarG8 = gVarE4.g(com.quizlet.data.repository.studysetwithcreatorinclass.f.b);
                Intrinsics.checkNotNullExpressionValue(gVarG8, "map(...)");
                return gVarG8;
            case 16:
                com.quizlet.data.repository.user.e eVar6 = (com.quizlet.data.repository.user.e) this.c;
                com.quizlet.data.repository.course.membership.c cVar5 = (com.quizlet.data.repository.course.membership.c) ((com.quizlet.data.repository.explanations.myexplanations.a) eVar6.b).c;
                List ids = kotlin.collections.A.b(Long.valueOf(this.b));
                Intrinsics.checkNotNullParameter(ids, "userIds");
                com.quizlet.quizletandroid.ui.activitycenter.views.i iVar = (com.quizlet.quizletandroid.ui.activitycenter.views.i) cVar5.a;
                Intrinsics.checkNotNullParameter(ids, "ids");
                io.reactivex.rxjava3.core.p<ApiThreeWrapper<UserResponse>> pVarD = ((com.quizlet.remote.service.E) iVar.b).d(com.google.android.gms.internal.mlkit_vision_barcode.U.c(ids));
                Intrinsics.checkNotNullParameter(pVarD, "<this>");
                com.quizlet.quizletandroid.ui.activitycenter.models.a mapper = (com.quizlet.quizletandroid.ui.activitycenter.models.a) cVar5.b;
                Intrinsics.checkNotNullParameter(mapper, "mapper");
                io.reactivex.rxjava3.internal.operators.single.g gVarG9 = pVarD.g(new C4636c(mapper, 8));
                Intrinsics.checkNotNullExpressionValue(gVarG9, "map(...)");
                io.reactivex.rxjava3.internal.operators.maybe.w wVarH = new io.reactivex.rxjava3.internal.operators.maybe.h(1, AbstractC3770y6.b(gVarG9), new com.quizlet.data.interactor.course.a(eVar6, 8)).h();
                Intrinsics.checkNotNullExpressionValue(wVarH, "toSingle(...)");
                return wVarH;
            default:
                com.quizlet.data.interactor.set.c cVar6 = (com.quizlet.data.interactor.set.c) this.c;
                com.quizlet.data.repository.explanations.textbook.a aVar8 = (com.quizlet.data.repository.explanations.textbook.a) cVar6.a;
                io.reactivex.rxjava3.subjects.d dVarZ = (io.reactivex.rxjava3.subjects.d) aVar8.c;
                if (dVarZ == null) {
                    dVarZ = io.reactivex.rxjava3.subjects.d.z();
                    aVar8.c = dVarZ;
                    Intrinsics.checkNotNullExpressionValue(dVarZ, "also(...)");
                }
                com.quizlet.data.connectivity.b bVarA = ((com.quizlet.remote.connectivity.b) ((com.quizlet.data.connectivity.a) aVar8.b)).a();
                io.reactivex.rxjava3.internal.functions.b bVar5 = io.reactivex.rxjava3.internal.functions.d.c;
                com.quizlet.infra.legacysyncengine.net.request.g gVar4 = io.reactivex.rxjava3.internal.functions.d.e;
                com.quizlet.infra.legacysyncengine.datasources.factory.a aVar9 = (com.quizlet.infra.legacysyncengine.datasources.factory.a) aVar8.d;
                com.quizlet.infra.legacysyncengine.datasources.factory.b bVar6 = (com.quizlet.infra.legacysyncengine.datasources.factory.b) aVar8.a;
                boolean z = bVarA.a;
                long j15 = this.b;
                if (z) {
                    com.quizlet.infra.legacysyncengine.datasources.w wVarA = bVar6.a(j15);
                    wVarA.e(aVar9);
                    iVarG = wVarA.d();
                } else {
                    com.quizlet.infra.legacysyncengine.datasources.w wVarA2 = bVar6.a(j15);
                    wVarA2.e(aVar9);
                    com.quizlet.infra.legacysyncengine.net.b bVar7 = com.quizlet.infra.legacysyncengine.net.b.a;
                    HashSet hashSetG = AbstractC3537t4.g(bVar7);
                    com.quizlet.infra.legacysyncengine.net.c cVar7 = wVarA2.b;
                    io.reactivex.rxjava3.subjects.p pVarC = cVar7.c(wVarA2.c, hashSetG);
                    io.reactivex.rxjava3.subjects.p pVarC2 = cVar7.c(wVarA2.d, AbstractC3537t4.g(bVar7));
                    pVarC.u(new com.quizlet.infra.legacysyncengine.datasources.t(wVarA2, 1), gVar4, bVar5);
                    iVarG = new io.reactivex.rxjava3.internal.operators.maybe.h(2, io.reactivex.rxjava3.core.i.r(pVarC, pVarC2), new com.quizlet.baserecyclerview.decoration.a(18)).g();
                }
                iVarG.u(new com.quizlet.quizletandroid.ui.setcreation.fragments.g(aVar8, j15, 1), gVar4, bVar5);
                C4905y c4905y = new C4905y(dVarZ, new com.quizlet.features.setpage.terms.a(cVar6, j15, 0), 1);
                Intrinsics.checkNotNullExpressionValue(c4905y, "doFinally(...)");
                return c4905y;
        }
    }
}

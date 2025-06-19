package com.braze.triggers.managers;

import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import androidx.compose.runtime.L0;
import androidx.navigation.U;
import androidx.work.impl.model.v;
import com.appsflyer.AFInAppEventType;
import com.appsflyer.AppsFlyerLib;
import com.braze.enums.Channel;
import com.braze.models.inappmessage.IInAppMessageZippedAssetHtml;
import com.braze.ui.actions.UriAction;
import com.braze.ui.actions.brazeactions.BrazeActionParser;
import com.braze.ui.actions.brazeactions.steps.StepData;
import com.braze.ui.inappmessage.utils.BackgroundInAppMessagePreparer;
import com.braze.ui.support.ViewUtils;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.ads.C1721Kc;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.google.android.gms.internal.mlkit_vision_barcode.Z;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3762x6;
import com.onetrust.otpublishers.headless.UI.fragment.q;
import com.quizlet.assembly.compose.buttons.InterfaceC4092q;
import com.quizlet.assembly.compose.menu.o;
import com.quizlet.assembly.compose.menu.s;
import com.quizlet.assembly.compose.menu.u;
import com.quizlet.data.model.C4127f1;
import com.quizlet.data.model.D;
import com.quizlet.data.model.W;
import com.quizlet.remote.model.base.ApiPostBody;
import com.quizlet.remote.model.explanations.feedback.RemoteExplanationsFeedback;
import com.quizlet.remote.service.InterfaceC4776c;
import io.reactivex.rxjava3.core.p;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.J;
import kotlin.ranges.IntRange;

/* loaded from: classes.dex */
public final /* synthetic */ class h implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ h(int i, Object obj, Object obj2) {
        this.a = i;
        this.c = obj;
        this.b = obj2;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        String str;
        p pVarG;
        p pVarG2;
        switch (this.a) {
            case 0:
                return a.a((com.braze.triggers.actions.a) this.c, (String) this.b);
            case 1:
                return b.a((String) this.b, (Map) this.c);
            case 2:
                return f.a((com.braze.triggers.events.b) this.c, (J) this.b);
            case 3:
                return UriAction.openUriWithActionView$lambda$4((Uri) this.c, (Bundle) this.b);
            case 4:
                return BrazeActionParser.execute$lambda$0((Channel) this.c, (Uri) this.b);
            case 5:
                return StepData.isArgCountInBounds$lambda$4((IntRange) this.c, (StepData) this.b);
            case 6:
                return BackgroundInAppMessagePreparer.prepareInAppMessageWithZippedAssetHtml$lambda$8((IInAppMessageZippedAssetHtml) this.c, (String) this.b);
            case 7:
                return ViewUtils.removeViewFromParent$lambda$1((View) this.c, (ViewGroup) this.b);
            case 8:
                ((U) this.b).invoke(Boolean.valueOf(((C1721Kc) this.c).b()));
                return Unit.a;
            case 9:
                ((androidx.constraintlayout.core.widgets.analyzer.f) this.c).b = false;
                Function0 function0 = (Function0) this.b;
                if (function0 != null) {
                    function0.invoke();
                }
                return Unit.a;
            case 10:
                ((androidx.constraintlayout.core.widgets.analyzer.f) this.c).b = false;
                ((com.perimeterx.mobile_sdk.doctor_app.d) this.b).invoke();
                return Unit.a;
            case 11:
                ((androidx.constraintlayout.core.widgets.analyzer.f) this.c).d((ArrayList) this.b);
                return Unit.a;
            case 12:
                com.quizlet.analytics.marketing.appsflyer.e eVar = (com.quizlet.analytics.marketing.appsflyer.e) ((com.quizlet.data.repository.classfolder.e) this.c).c;
                com.quizlet.infra.contracts.marketing.a event = (com.quizlet.infra.contracts.marketing.a) this.b;
                Intrinsics.checkNotNullParameter(event, "event");
                AppsFlyerLib appsFlyerLib = AppsFlyerLib.getInstance();
                Intrinsics.checkNotNullExpressionValue(appsFlyerLib, "getInstance(...)");
                int iOrdinal = event.ordinal();
                if (iOrdinal == 0) {
                    str = AFInAppEventType.COMPLETE_REGISTRATION;
                } else if (iOrdinal == 1) {
                    str = AFInAppEventType.START_TRIAL;
                } else if (iOrdinal == 2) {
                    str = AFInAppEventType.LOGIN;
                } else {
                    if (iOrdinal != 3) {
                        throw new NoWhenBranchMatchedException();
                    }
                    str = AFInAppEventType.PURCHASE;
                }
                appsFlyerLib.logEvent(eVar.a, str, new HashMap());
                return Unit.a;
            case 13:
                if (((InterfaceC4092q) this.c).b()) {
                    ((Function0) this.b).invoke();
                }
                return Unit.a;
            case 14:
                ((Function1) this.c).invoke(((com.quizlet.ui.models.content.carditem.b) this.b).a);
                return Unit.a;
            case 15:
                ((Function1) this.c).invoke(Long.valueOf(((com.quizlet.ui.models.content.carditem.c) this.b).a));
                return Unit.a;
            case 16:
                ((Function1) this.c).invoke(((com.quizlet.ui.models.content.carditem.d) this.b).a);
                return Unit.a;
            case 17:
                ((Function1) this.c).invoke((com.quizlet.assembly.compose.components.flashcards.b) this.b);
                return Unit.a;
            case 18:
                ((Function1) this.c).invoke((o) this.b);
                return Unit.a;
            case 19:
                s sVar = (s) this.b;
                ((Function0) this.c).invoke();
                ((L0) sVar.c).setValue(u.b);
                return Unit.a;
            case 20:
                com.quizlet.data.repository.explanations.exercise.b bVar = (com.quizlet.data.repository.explanations.exercise.b) ((com.quizlet.data.interactor.school.b) this.c).b;
                String id = (String) this.b;
                Intrinsics.checkNotNullParameter(id, "id");
                io.reactivex.rxjava3.internal.operators.maybe.e eVar2 = new io.reactivex.rxjava3.internal.operators.maybe.e(new com.google.firebase.tracing.a(id, 8, bVar), 0);
                Intrinsics.checkNotNullExpressionValue(eVar2, "create(...)");
                io.reactivex.rxjava3.internal.operators.single.d dVar = new io.reactivex.rxjava3.internal.operators.single.d(new io.reactivex.rxjava3.internal.operators.flowable.b(new com.quizlet.data.repository.classfolder.b(1, bVar, id), 4), new com.quizlet.billing.manager.b(2, bVar, id), 2);
                Intrinsics.checkNotNullExpressionValue(dVar, "doOnSuccess(...)");
                io.reactivex.rxjava3.internal.operators.maybe.e eVar3 = new io.reactivex.rxjava3.internal.operators.maybe.e(AbstractC3762x6.c(dVar, (org.slf4j.b) bVar.c, "Error retrieving exercise details from remote"), 3);
                Intrinsics.checkNotNullExpressionValue(eVar3, "toMaybe(...)");
                io.reactivex.rxjava3.internal.operators.flowable.b bVar2 = new io.reactivex.rxjava3.internal.operators.flowable.b(io.reactivex.rxjava3.core.g.b(eVar2, eVar3), 0);
                Intrinsics.checkNotNullExpressionValue(bVar2, "firstOrError(...)");
                return bVar2;
            case 21:
                com.quizlet.login.common.interactors.d dVar2 = (com.quizlet.login.common.interactors.d) ((com.quizlet.data.repository.activitycenter.b) this.c).b;
                W data = (W) this.b;
                Intrinsics.checkNotNullParameter(data, "data");
                RemoteExplanationsFeedback data2 = com.quizlet.quizletandroid.ui.setcreation.adapters.a.d(data);
                androidx.work.impl.model.c cVar = (androidx.work.impl.model.c) dVar2.b;
                Intrinsics.checkNotNullParameter(data2, "data");
                io.reactivex.rxjava3.core.a aVarC = ((com.quizlet.remote.service.l) cVar.b).c(data2);
                aVarC.getClass();
                io.reactivex.rxjava3.internal.operators.completable.c cVar2 = new io.reactivex.rxjava3.internal.operators.completable.c(aVarC, 9);
                Intrinsics.checkNotNullExpressionValue(cVar2, "onErrorComplete(...)");
                return cVar2;
            case EventType.WINDOW_STATE /* 22 */:
                com.quizlet.data.repository.explanations.question.a aVar = (com.quizlet.data.repository.explanations.question.a) ((com.quizlet.data.repository.qclass.c) this.c).b;
                String id2 = (String) this.b;
                Intrinsics.checkNotNullParameter(id2, "id");
                io.reactivex.rxjava3.internal.operators.maybe.e eVar4 = new io.reactivex.rxjava3.internal.operators.maybe.e(new com.google.firebase.tracing.a(id2, 9, aVar), 0);
                Intrinsics.checkNotNullExpressionValue(eVar4, "create(...)");
                io.reactivex.rxjava3.internal.operators.single.d dVar3 = new io.reactivex.rxjava3.internal.operators.single.d(new io.reactivex.rxjava3.internal.operators.flowable.b(new com.quizlet.data.repository.classfolder.b(2, aVar, id2), 4), new com.quizlet.billing.manager.b(3, aVar, id2), 2);
                Intrinsics.checkNotNullExpressionValue(dVar3, "doOnSuccess(...)");
                io.reactivex.rxjava3.internal.operators.maybe.e eVar5 = new io.reactivex.rxjava3.internal.operators.maybe.e(AbstractC3762x6.c(dVar3, (org.slf4j.b) aVar.c, "Error retrieving question by id from remote"), 3);
                Intrinsics.checkNotNullExpressionValue(eVar5, "toMaybe(...)");
                io.reactivex.rxjava3.internal.operators.flowable.b bVar3 = new io.reactivex.rxjava3.internal.operators.flowable.b(io.reactivex.rxjava3.core.g.b(eVar4, eVar5), 0);
                Intrinsics.checkNotNullExpressionValue(bVar3, "firstOrError(...)");
                return bVar3;
            case EventType.AUDIO /* 23 */:
                com.quizlet.data.repository.explanations.textbook.a aVar2 = (com.quizlet.data.repository.explanations.textbook.a) ((com.quizlet.data.repository.widget.b) this.c).b;
                String isbn = (String) this.b;
                Intrinsics.checkNotNullParameter(isbn, "isbn");
                io.reactivex.rxjava3.internal.operators.maybe.e eVar6 = new io.reactivex.rxjava3.internal.operators.maybe.e(new com.google.firebase.tracing.a(isbn, 10, aVar2), 0);
                Intrinsics.checkNotNullExpressionValue(eVar6, "create(...)");
                io.reactivex.rxjava3.internal.operators.single.d dVar4 = new io.reactivex.rxjava3.internal.operators.single.d(new io.reactivex.rxjava3.internal.operators.flowable.b(new com.quizlet.data.repository.classfolder.b(3, aVar2, isbn), 4), new com.quizlet.billing.manager.b(4, aVar2, isbn), 2);
                Intrinsics.checkNotNullExpressionValue(dVar4, "doOnSuccess(...)");
                io.reactivex.rxjava3.internal.operators.maybe.e eVar7 = new io.reactivex.rxjava3.internal.operators.maybe.e(AbstractC3762x6.c(dVar4, (org.slf4j.b) aVar2.c, "Error retrieving textbook from remote"), 3);
                Intrinsics.checkNotNullExpressionValue(eVar7, "toMaybe(...)");
                io.reactivex.rxjava3.internal.operators.flowable.b bVar4 = new io.reactivex.rxjava3.internal.operators.flowable.b(io.reactivex.rxjava3.core.g.b(eVar6, eVar7), 0);
                Intrinsics.checkNotNullExpressionValue(bVar4, "firstOrError(...)");
                return bVar4;
            case EventType.VIDEO /* 24 */:
                com.quizlet.data.repository.folderset.c cVar3 = (com.quizlet.data.repository.folderset.c) ((com.quizlet.data.repository.searchexplanations.c) this.c).b;
                List setIds = (List) this.b;
                Intrinsics.checkNotNullParameter(setIds, "studySetIds");
                com.quizlet.data.repository.explanations.myexplanations.a aVar3 = (com.quizlet.data.repository.explanations.myexplanations.a) ((q) cVar3.b).b;
                Intrinsics.checkNotNullParameter(setIds, "studySetIds");
                com.quizlet.quizletandroid.ui.setcreation.managers.n nVar = (com.quizlet.quizletandroid.ui.setcreation.managers.n) aVar3.b;
                Intrinsics.checkNotNullParameter(setIds, "setIds");
                io.reactivex.rxjava3.internal.operators.single.g gVarG = ((com.quizlet.remote.service.n) nVar.b).c(null, com.google.android.gms.internal.mlkit_vision_barcode.U.c(setIds)).g(new com.quizlet.remote.model.folderset.a(aVar3, null));
                Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
                return cVar3.n(gVarG);
            case EventType.SUBS /* 25 */:
                io.reactivex.rxjava3.internal.operators.observable.J jQ = ((com.quizlet.data.repository.folderwithcreator.e) ((com.quizlet.data.interactor.folderwithcreator.m) this.c).a).h((List) this.b).q(com.quizlet.data.interactor.folderwithcreator.i.a);
                Intrinsics.checkNotNullExpressionValue(jQ, "map(...)");
                return jQ;
            case EventType.CDN /* 26 */:
                com.quizlet.data.repository.login.a aVar4 = (com.quizlet.data.repository.login.a) ((v) this.c).b;
                String email = (String) this.b;
                Intrinsics.checkNotNullParameter(email, "email");
                io.reactivex.rxjava3.internal.operators.flowable.b bVar5 = new io.reactivex.rxjava3.internal.operators.flowable.b(new com.quizlet.data.repository.classfolder.b(5, aVar4, email), 4);
                Intrinsics.checkNotNullExpressionValue(bVar5, "defer(...)");
                return AbstractC3762x6.c(bVar5, (org.slf4j.b) aVar4.c, "Error from checking email validity");
            case 27:
                com.quizlet.data.repository.set.f fVar = (com.quizlet.data.repository.set.f) this.c;
                com.quizlet.data.repository.progress.b bVar6 = (com.quizlet.data.repository.progress.b) fVar.b;
                C4127f1 progressReset = (C4127f1) this.b;
                bVar6.getClass();
                Intrinsics.checkNotNullParameter(progressReset, "progressReset");
                io.reactivex.rxjava3.internal.operators.completable.a aVar5 = new io.reactivex.rxjava3.internal.operators.completable.a(0, ((com.quizlet.data.repository.folderwithcreator.e) bVar6.b).r(progressReset), ((com.quizlet.remote.model.progress.e) bVar6.a).d(progressReset));
                Intrinsics.checkNotNullExpressionValue(aVar5, "andThen(...)");
                com.quizlet.billing.manager.b bVar7 = new com.quizlet.billing.manager.b(1, fVar, progressReset);
                com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.d;
                io.reactivex.rxjava3.internal.functions.b bVar8 = io.reactivex.rxjava3.internal.functions.d.c;
                io.reactivex.rxjava3.internal.operators.completable.c cVar4 = new io.reactivex.rxjava3.internal.operators.completable.c(new io.reactivex.rxjava3.internal.operators.completable.i(aVar5, gVar, bVar7, bVar8, bVar8), 9);
                Intrinsics.checkNotNullExpressionValue(cVar4, "onErrorComplete(...)");
                return cVar4;
            case 28:
                io.reactivex.rxjava3.internal.operators.single.g gVarE = ((io.reactivex.rxjava3.internal.operators.single.g) this.b).e(new com.google.android.material.floatingactionbutton.c((com.quizlet.data.repository.classfolder.e) this.c, 12));
                Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
                return gVarE;
            default:
                List list = (List) this.b;
                Intrinsics.d(list);
                com.quizlet.data.repository.classfolder.e eVar8 = (com.quizlet.data.repository.classfolder.e) this.c;
                com.quizlet.data.repository.widget.b bVar9 = (com.quizlet.data.repository.widget.b) ((com.quizlet.data.repository.explanations.myexplanations.a) eVar8.b).c;
                ArrayList arrayListM = assistantMode.refactored.a.m("classFolders", list);
                ArrayList arrayList = new ArrayList();
                for (Object obj : list) {
                    D d = (D) obj;
                    if (d.i) {
                        if (Intrinsics.b(d.f, Boolean.TRUE) && d.b > 0 && d.c > 0) {
                            arrayListM.add(obj);
                        }
                    }
                    arrayList.add(obj);
                }
                boolean zIsEmpty = arrayListM.isEmpty();
                com.quizlet.login.authentication.login.a aVar6 = (com.quizlet.login.authentication.login.a) bVar9.b;
                com.quizlet.quizletandroid.ui.folder.logging.a aVar7 = (com.quizlet.quizletandroid.ui.folder.logging.a) bVar9.c;
                InterfaceC4776c interfaceC4776c = (InterfaceC4776c) aVar6.b;
                if (zIsEmpty) {
                    pVarG = p.f(K.a);
                } else {
                    ArrayList data3 = T.g(aVar7, arrayListM);
                    Intrinsics.checkNotNullParameter(data3, "data");
                    pVarG = interfaceC4776c.b(new ApiPostBody<>(data3)).g(new com.quizlet.remote.model.classfolder.a(bVar9, data3));
                    Intrinsics.checkNotNullExpressionValue(pVarG, "map(...)");
                }
                if (arrayList.isEmpty()) {
                    pVarG2 = p.f(K.a);
                } else {
                    ArrayList data4 = T.g(aVar7, arrayList);
                    Intrinsics.checkNotNullParameter(data4, "data");
                    pVarG2 = interfaceC4776c.d(new ApiPostBody<>(data4)).g(new com.quizlet.remote.model.classfolder.a(bVar9, data4));
                    Intrinsics.checkNotNullExpressionValue(pVarG2, "map(...)");
                }
                io.reactivex.rxjava3.internal.operators.single.g gVarE2 = Z.b(pVarG, pVarG2).e(new com.google.android.material.floatingactionbutton.c(eVar8, 12));
                Intrinsics.checkNotNullExpressionValue(gVarE2, "flatMap(...)");
                return gVarE2;
        }
    }

    public /* synthetic */ h(String str, Map map) {
        this.a = 1;
        this.b = str;
        this.c = map;
    }
}

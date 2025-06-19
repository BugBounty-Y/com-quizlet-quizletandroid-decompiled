package com.quizlet.data.repository.explanations.exercise;

import android.content.Context;
import android.content.Intent;
import androidx.compose.material3.L3;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.navigation.U;
import androidx.work.impl.model.c;
import androidx.work.impl.model.e;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.google.android.gms.internal.mlkit_vision_barcode.Y;
import com.google.android.gms.internal.mlkit_vision_barcode.Z;
import com.google.android.gms.internal.mlkit_vision_document_scanner.J5;
import com.google.firebase.crashlytics.internal.common.j;
import com.onetrust.otpublishers.headless.UI.fragment.q;
import com.quizlet.assembly.compose.menu.s;
import com.quizlet.data.interactor.achievements.f;
import com.quizlet.data.model.AbstractC4119d0;
import com.quizlet.data.model.C4123e0;
import com.quizlet.data.model.C4124e1;
import com.quizlet.data.model.FlashcardsInfo;
import com.quizlet.data.model.OutlineMarkdownInfo;
import com.quizlet.data.model.ReviewSheetInfo;
import com.quizlet.data.model.SimpleImage;
import com.quizlet.data.model.V0;
import com.quizlet.data.repository.folder.i;
import com.quizlet.eventlogger.features.explanations.ExplanationsLogger;
import com.quizlet.eventlogger.model.ExplanationsEventLog;
import com.quizlet.explanations.feedback.data.ExplanationsFeedbackSetUpState;
import com.quizlet.features.flashcards.S;
import com.quizlet.features.folders.data.C4280f;
import com.quizlet.features.folders.data.J;
import com.quizlet.features.folders.data.Q0;
import com.quizlet.features.notes.common.events.C4371b;
import com.quizlet.features.notes.paywall.ScanNotesPaywallActivity;
import com.quizlet.features.onboarding.survey.m;
import com.quizlet.features.questionnaire.navigation.Control;
import com.quizlet.quizletandroid.ui.login.h;
import com.quizlet.quizletandroid.ui.setcreation.managers.n;
import com.quizlet.remote.model.base.ApiPostBody;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.explanations.exercise.ExerciseDetailsResponse;
import com.quizlet.remote.model.explanations.question.QuestionResponse;
import com.quizlet.remote.model.login.ValidateEmailRequest;
import com.quizlet.remote.service.l;
import com.quizlet.studiablemodels.StudiableText;
import com.quizlet.ui.models.content.listitem.o;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.internal.operators.single.g;
import java.util.ArrayList;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.collections.C4927s;
import kotlin.collections.K;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ a(int i, Object obj, Object obj2) {
        this.a = i;
        this.c = obj;
        this.b = obj2;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        p pVarG;
        p pVarG2;
        ExplanationsLogger.EventData eventData;
        Object jVar;
        Object obj = this.c;
        Object obj2 = this.b;
        switch (this.a) {
            case 0:
                e eVar = (e) ((com.quizlet.data.interactor.course.a) ((b) obj).a).b;
                String id = (String) obj2;
                Intrinsics.checkNotNullParameter(id, "id");
                c cVar = (c) eVar.b;
                Intrinsics.checkNotNullParameter(id, "id");
                p<ApiThreeWrapper<ExerciseDetailsResponse>> pVarG3 = ((l) cVar.b).g(id);
                String strB = android.support.v4.media.session.a.B("No exercise details found with id {", id, "}");
                g gVarE = pVarG3.e(new com.quizlet.remote.model.explanations.exercise.a(eVar, strB));
                Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
                return Y.b(gVarE, strB);
            case 1:
                androidx.work.impl.model.l lVar = (androidx.work.impl.model.l) ((com.google.firebase.crashlytics.internal.settings.b) ((com.quizlet.data.repository.explanations.question.a) obj).a).b;
                String id2 = (String) obj2;
                Intrinsics.checkNotNullParameter(id2, "id");
                c cVar2 = (c) lVar.b;
                Intrinsics.checkNotNullParameter(id2, "id");
                p<ApiThreeWrapper<QuestionResponse>> pVarF = ((l) cVar2.b).f(id2);
                String strB2 = android.support.v4.media.session.a.B("No question found with id (", id2, ")");
                g gVarE2 = pVarF.e(new com.quizlet.remote.model.explanations.question.a(lVar, strB2));
                Intrinsics.checkNotNullExpressionValue(gVarE2, "flatMap(...)");
                return Y.b(gVarE2, strB2);
            case 2:
                com.quizlet.data.interactor.school.b bVar = (com.quizlet.data.interactor.school.b) ((f) ((com.quizlet.data.repository.explanations.textbook.a) obj).a).b;
                String isbn = (String) obj2;
                Intrinsics.checkNotNullParameter(isbn, "isbn");
                c cVar3 = (c) bVar.b;
                Intrinsics.checkNotNullParameter(isbn, "isbn");
                g gVarE3 = ((l) cVar3.b).e(isbn, true).e(new com.quizlet.remote.model.explanations.textbook.a(bVar, isbn));
                Intrinsics.checkNotNullExpressionValue(gVarE3, "flatMap(...)");
                return Y.b(gVarE3, "No textbook found with isbn (" + isbn + ")");
            case 3:
                i iVar = (i) obj;
                g gVarE4 = ((com.quizlet.remote.model.folder.p) iVar.a.c).f(A.b((AbstractC4119d0) obj2)).e(new j(iVar, 11));
                Intrinsics.checkNotNullExpressionValue(gVarE4, "flatMap(...)");
                return gVarE4;
            case 4:
                com.quizlet.data.repository.explanations.myexplanations.a aVar = (com.quizlet.data.repository.explanations.myexplanations.a) ((q) ((com.quizlet.data.repository.folderset.c) obj).b).b;
                List folderSets = (List) obj2;
                Intrinsics.d(folderSets);
                Intrinsics.checkNotNullParameter(folderSets, "folderSets");
                ArrayList folderSets2 = new ArrayList();
                ArrayList arrayList = new ArrayList();
                for (Object obj3 : folderSets) {
                    C4123e0 c4123e0 = (C4123e0) obj3;
                    if (c4123e0.h) {
                        if (Intrinsics.b(c4123e0.e, Boolean.TRUE) && c4123e0.c > 0 && c4123e0.b > 0) {
                            folderSets2.add(obj3);
                        }
                    }
                    arrayList.add(obj3);
                }
                Intrinsics.checkNotNullParameter(folderSets2, "folderSets");
                boolean zIsEmpty = folderSets2.isEmpty();
                n nVar = (n) aVar.b;
                com.quizlet.quizletandroid.ui.joincontenttofolder.j jVar2 = (com.quizlet.quizletandroid.ui.joincontenttofolder.j) aVar.c;
                com.quizlet.remote.service.n nVar2 = (com.quizlet.remote.service.n) nVar.b;
                if (zIsEmpty) {
                    pVarG = p.f(K.a);
                } else {
                    ArrayList folderSets3 = T.g(jVar2, folderSets2);
                    Intrinsics.checkNotNullParameter(folderSets3, "folderSets");
                    pVarG = nVar2.a(new ApiPostBody<>(folderSets3)).g(new com.quizlet.remote.model.folderset.a(aVar, folderSets3));
                    Intrinsics.checkNotNullExpressionValue(pVarG, "map(...)");
                }
                if (arrayList.isEmpty()) {
                    pVarG2 = p.f(K.a);
                } else {
                    ArrayList data = T.g(jVar2, arrayList);
                    Intrinsics.checkNotNullParameter(data, "data");
                    pVarG2 = nVar2.b(new ApiPostBody<>(data)).g(new com.quizlet.remote.model.folderset.a(aVar, data));
                    Intrinsics.checkNotNullExpressionValue(pVarG2, "map(...)");
                }
                return Z.b(pVarG, pVarG2);
            case 5:
                h hVar = (h) ((com.quizlet.data.repository.login.a) obj).a;
                String email = (String) obj2;
                Intrinsics.checkNotNullParameter(email, "email");
                com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c cVar4 = (com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c) hVar.b;
                Intrinsics.checkNotNullParameter(email, "email");
                g gVarG = ((com.quizlet.remote.service.A) cVar4.b).a(new ValidateEmailRequest(email)).g(new com.quizlet.quizletandroid.ui.profile.b());
                Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
                return gVarG;
            case 6:
                com.quizlet.explanations.feedback.viewmodel.a aVar2 = (com.quizlet.explanations.feedback.viewmodel.a) obj;
                ExplanationsFeedbackSetUpState explanationsFeedbackSetUpState = (ExplanationsFeedbackSetUpState) obj2;
                if (explanationsFeedbackSetUpState instanceof ExplanationsFeedbackSetUpState.Exercise) {
                    ExplanationsFeedbackSetUpState.Exercise exercise = (ExplanationsFeedbackSetUpState.Exercise) explanationsFeedbackSetUpState;
                    eventData = new ExplanationsLogger.EventData.Exercise(exercise.c, exercise.d, exercise.b);
                } else {
                    if (!(explanationsFeedbackSetUpState instanceof ExplanationsFeedbackSetUpState.Question)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    ExplanationsFeedbackSetUpState.Question question = (ExplanationsFeedbackSetUpState.Question) explanationsFeedbackSetUpState;
                    eventData = new ExplanationsLogger.EventData.Question(question.b, question.c);
                }
                String strA = explanationsFeedbackSetUpState.a();
                ExplanationsLogger explanationsLogger = aVar2.e;
                explanationsLogger.getClass();
                Intrinsics.checkNotNullParameter(eventData, "eventData");
                ExplanationsEventLog.Companion companion = ExplanationsEventLog.b;
                com.quizlet.eventlogger.features.explanations.a aVar3 = new com.quizlet.eventlogger.features.explanations.a(4, eventData, explanationsLogger, strA);
                companion.getClass();
                explanationsLogger.a(ExplanationsEventLog.Companion.a("explanations_feedback", aVar3));
                aVar2.f.j(com.quizlet.explanations.feedback.data.c.b);
                return Unit.a;
            case 7:
                ((com.quizlet.explanations.questiondetail.recyclerview.g) obj).a().invoke(((SimpleImage) obj2).a);
                return Unit.a;
            case 8:
                U u = (U) obj;
                if (u != null) {
                    u.invoke((com.quizlet.explanations.solution.recyclerview.step.c) obj2);
                }
                return Unit.a;
            case 9:
                boolean zBooleanValue = ((Boolean) ((InterfaceC0773a0) obj2).getValue()).booleanValue();
                com.quizlet.explanations.textbook.viewmodel.c cVar5 = (com.quizlet.explanations.textbook.viewmodel.c) obj;
                C4927s c4927s = cVar5.n;
                if (c4927s.isEmpty()) {
                    jVar = com.quizlet.explanations.textbook.data.h.a;
                } else if (zBooleanValue) {
                    Intrinsics.checkNotNullParameter("ExerciseBackStackTag", "tag");
                    jVar = new com.quizlet.explanations.textbook.data.j();
                } else {
                    c4927s.removeLast();
                    jVar = com.quizlet.explanations.textbook.data.i.a;
                }
                cVar5.h.j(jVar);
                return Unit.a;
            case 10:
                S s = (S) obj;
                s.w.l("settings");
                s.y = false;
                s.F();
                ((Function0) obj2).invoke();
                return Unit.a;
            case 11:
                ((Function1) obj).invoke(((StudiableText) obj2).a);
                return Unit.a;
            case 12:
                J5.a((s) obj, (ArrayList) obj2);
                return Unit.a;
            case 13:
                ((Function1) obj).invoke(new C4280f(((Q0) obj2).e));
                return Unit.a;
            case 14:
                ((Function1) obj).invoke(J.a);
                ((s) obj2).b();
                return Unit.a;
            case 15:
                if (((String) obj2) == null) {
                    ((Function0) obj).invoke();
                }
                return Unit.a;
            case 16:
                ((Function1) obj).invoke(((C4124e1) obj2).c);
                return Unit.a;
            case 17:
                ((Function1) obj).invoke((o) obj2);
                return Unit.a;
            case 18:
                ((Function1) obj).invoke((com.quizlet.features.infra.folder.menu.data.g) obj2);
                return Unit.a;
            case 19:
                ((Function1) obj).invoke((com.quizlet.features.infra.folder.study.data.a) obj2);
                return Unit.a;
            case 20:
                Function0 function0 = ((com.quizlet.features.infra.snackbar.composables.a) obj).a.e;
                if (function0 != null) {
                    function0.invoke();
                }
                ((L3) obj2).a();
                return Unit.a;
            case 21:
                ((Function1) obj).invoke(new C4371b(((com.quizlet.features.notes.data.f) obj2).e));
                return Unit.a;
            case EventType.WINDOW_STATE /* 22 */:
                OutlineMarkdownInfo outlineMarkdownInfo = (OutlineMarkdownInfo) obj;
                if (outlineMarkdownInfo != null) {
                    ((Function1) obj2).invoke(new com.quizlet.features.notes.common.events.s(outlineMarkdownInfo));
                }
                return Unit.a;
            case EventType.AUDIO /* 23 */:
                FlashcardsInfo flashcardsInfo = (FlashcardsInfo) obj;
                if (flashcardsInfo != null) {
                    ((Function1) obj2).invoke(new com.quizlet.features.notes.common.events.s(flashcardsInfo));
                }
                return Unit.a;
            case EventType.VIDEO /* 24 */:
                ReviewSheetInfo reviewSheetInfo = (ReviewSheetInfo) obj;
                if (reviewSheetInfo != null) {
                    ((Function1) obj2).invoke(new com.quizlet.features.notes.common.events.s(reviewSheetInfo));
                }
                return Unit.a;
            case EventType.SUBS /* 25 */:
                com.quizlet.quizletandroid.ui.navigationmanagers.e eVar2 = (com.quizlet.quizletandroid.ui.navigationmanagers.e) ((com.quizlet.features.notes.manager.a) obj);
                eVar2.getClass();
                int i = ScanNotesPaywallActivity.k;
                Context context = eVar2.a;
                Intrinsics.checkNotNullParameter(context, "context");
                eVar2.b(new Intent(context, (Class<?>) ScanNotesPaywallActivity.class));
                ((Function0) obj2).invoke();
                return Unit.a;
            case EventType.CDN /* 26 */:
                ((Function1) obj).invoke((m) obj2);
                return Unit.a;
            case 27:
                ((Function1) obj).invoke(Integer.valueOf(((com.quizlet.features.practicetest.common.data.i) obj2).a));
                return Unit.a;
            case 28:
                ((Function1) obj).invoke(((V0) obj2).a);
                return Unit.a;
            default:
                Control.Button button = (Control.Button) obj2;
                String payload = button.e;
                com.quizlet.features.questionnaire.steps.a aVar4 = (com.quizlet.features.questionnaire.steps.a) obj;
                aVar4.getClass();
                Intrinsics.checkNotNullParameter(payload, "payload");
                com.quizlet.data.interactor.course.a aVar5 = aVar4.c;
                aVar5.getClass();
                Intrinsics.checkNotNullParameter(payload, "payload");
                ((com.quizlet.usecase.a) ((com.quizlet.usecase.b) aVar5.b)).a(new com.quizlet.features.questionnaire.navigation.n(payload, button.c));
                return Unit.a;
        }
    }

    public /* synthetic */ a(String str, Function0 function0) {
        this.a = 15;
        this.b = str;
        this.c = function0;
    }
}

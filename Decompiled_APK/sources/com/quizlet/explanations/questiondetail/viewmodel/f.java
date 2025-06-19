package com.quizlet.explanations.questiondetail.viewmodel;

import androidx.compose.ui.input.pointer.u;
import androidx.lifecycle.Y;
import androidx.lifecycle.m0;
import com.braze.triggers.managers.h;
import com.google.android.gms.internal.mlkit_vision_barcode.B7;
import com.google.android.gms.internal.mlkit_vision_barcode.C6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.h7;
import com.google.firebase.messaging.p;
import com.quizlet.assembly.compose.buttons.Z;
import com.quizlet.data.model.C4151n1;
import com.quizlet.data.model.Question;
import com.quizlet.data.model.X;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.eventlogger.features.explanations.ExplanationsLogger;
import com.quizlet.eventlogger.features.folder.FolderLogger;
import com.quizlet.explanations.questiondetail.data.QuestionDetailSetUpState;
import com.quizlet.explanations.questiondetail.recyclerview.g;
import com.quizlet.explanations.questiondetail.recyclerview.l;
import com.quizlet.explanations.questiondetail.recyclerview.m;
import io.reactivex.rxjava3.subjects.r;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes2.dex */
public final class f extends com.quizlet.viewmodel.a {
    public Question A;
    public X B;
    public final com.quizlet.data.repository.qclass.c d;
    public final com.quizlet.data.repository.searchexplanations.c e;
    public final com.quizlet.data.repository.folderset.c f;
    public final ExplanationsLogger g;
    public final UserInfoCache h;
    public final androidx.work.impl.model.c i;
    public final com.quizlet.data.repository.searchexplanations.c j;
    public final com.quizlet.time.b k;
    public final p l;
    public final QuestionDetailSetUpState m;
    public final String n;
    public final Y o;
    public final Y p;
    public final Y q;
    public final Y r;
    public final Y s;
    public final androidx.lifecycle.X t;
    public final androidx.lifecycle.X u;
    public final Y v;
    public final androidx.lifecycle.X w;
    public final androidx.lifecycle.X x;
    public final androidx.lifecycle.X y;
    public final s0 z;

    public f(m0 savedStateHandle, com.quizlet.data.repository.qclass.c getQuestionUseCase, com.quizlet.data.repository.searchexplanations.c getTextbookRecommendationsUseCase, com.quizlet.data.repository.folderset.c saveMyRecentExplanationItemUseCase, ExplanationsLogger explanationsLogger, UserInfoCache userInfoCache, androidx.work.impl.model.c userProperties, com.quizlet.data.repository.searchexplanations.c shareExplanationsHelper, p blurringPaywallSolutionsFeature, FolderLogger folderEventLogger) {
        int i = 1;
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(getQuestionUseCase, "getQuestionUseCase");
        Intrinsics.checkNotNullParameter(getTextbookRecommendationsUseCase, "getTextbookRecommendationsUseCase");
        Intrinsics.checkNotNullParameter(saveMyRecentExplanationItemUseCase, "saveMyRecentExplanationItemUseCase");
        Intrinsics.checkNotNullParameter(explanationsLogger, "explanationsLogger");
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(shareExplanationsHelper, "shareExplanationsHelper");
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
        Intrinsics.checkNotNullParameter(blurringPaywallSolutionsFeature, "blurringPaywallSolutionsFeature");
        Intrinsics.checkNotNullParameter(folderEventLogger, "folderEventLogger");
        this.d = getQuestionUseCase;
        this.e = getTextbookRecommendationsUseCase;
        this.f = saveMyRecentExplanationItemUseCase;
        this.g = explanationsLogger;
        this.h = userInfoCache;
        this.i = userProperties;
        this.j = shareExplanationsHelper;
        this.k = timeProvider;
        this.l = blurringPaywallSolutionsFeature;
        QuestionDetailSetUpState questionDetailSetUpState = (QuestionDetailSetUpState) savedStateHandle.a("question_detail_set_up_state");
        if (questionDetailSetUpState == null) {
            throw new IllegalStateException("Missing required argument (question_detail_set_up_state)");
        }
        this.m = questionDetailSetUpState;
        String str = (String) savedStateHandle.a("question_detail_screen_name");
        if (str == null) {
            throw new IllegalStateException("Missing required argument (question_detail_screen_name)");
        }
        this.n = str;
        this.o = new Y();
        this.p = new Y();
        this.q = new Y();
        Y y = new Y(Boolean.FALSE);
        this.r = y;
        Y y2 = new Y();
        this.s = y2;
        this.t = C6.a(B.j(y, y2), new u(this, i));
        this.u = new androidx.lifecycle.X(1);
        this.v = new Y();
        this.w = new androidx.lifecycle.X(1);
        this.x = new androidx.lifecycle.X(1);
        this.y = new androidx.lifecycle.X(1);
        this.z = e0.c(new com.quizlet.explanations.questiondetail.data.a(false, ""));
        B();
        folderEventLogger.setScreenName("expert_solutions_question");
    }

    public final void B() {
        this.o.j(Boolean.TRUE);
        final int i = 0;
        Function1 withId = new Function1(this) { // from class: com.quizlet.explanations.questiondetail.viewmodel.a
            public final /* synthetic */ f b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                switch (i) {
                    case 0:
                        String id = (String) obj;
                        Intrinsics.checkNotNullParameter(id, "id");
                        f fVar = this.b;
                        com.quizlet.data.repository.qclass.c cVar = fVar.d;
                        cVar.getClass();
                        Intrinsics.checkNotNullParameter(id, "id");
                        r stopToken = fVar.c;
                        Intrinsics.checkNotNullParameter(stopToken, "stopToken");
                        return ((androidx.work.impl.model.c) cVar.c).c(stopToken, new h(22, cVar, id));
                    case 1:
                        Throwable error = (Throwable) obj;
                        Intrinsics.checkNotNullParameter(error, "error");
                        f fVar2 = this.b;
                        QuestionDetailSetUpState questionDetailSetUpState = fVar2.m;
                        Z withId2 = new Z(26);
                        questionDetailSetUpState.getClass();
                        Intrinsics.checkNotNullParameter(withId2, "withId");
                        if (!(questionDetailSetUpState instanceof QuestionDetailSetUpState.WithId)) {
                            throw new NoWhenBranchMatchedException();
                        }
                        Object objInvoke = withId2.invoke(((QuestionDetailSetUpState.WithId) questionDetailSetUpState).a);
                        boolean z = error instanceof NoSuchElementException;
                        Y y = fVar2.v;
                        if (z) {
                            timber.log.c.a.i(error, "Question for (" + objInvoke + ") does not exist", new Object[0]);
                            y.j(com.quizlet.uicommon.ui.states.a.c);
                        } else {
                            y.j(com.quizlet.uicommon.ui.states.a.b);
                        }
                        return Unit.a;
                    default:
                        C4151n1 it2 = (C4151n1) obj;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        f fVar3 = this.b;
                        String str = fVar3.n;
                        androidx.work.impl.model.c cVar2 = fVar3.i;
                        io.reactivex.rxjava3.internal.observers.e eVarI = io.reactivex.rxjava3.core.p.o(cVar2.r(), cVar2.t(), fVar3.l.y(cVar2), b.a).i(new c(it2, fVar3, str), io.reactivex.rxjava3.internal.functions.d.e);
                        Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
                        Intrinsics.checkNotNullParameter(eVarI, "<this>");
                        fVar3.A(eVarI);
                        return Unit.a;
                }
            }
        };
        QuestionDetailSetUpState questionDetailSetUpState = this.m;
        questionDetailSetUpState.getClass();
        Intrinsics.checkNotNullParameter(withId, "withId");
        if (!(questionDetailSetUpState instanceof QuestionDetailSetUpState.WithId)) {
            throw new NoWhenBranchMatchedException();
        }
        io.reactivex.rxjava3.internal.operators.single.e eVar = new io.reactivex.rxjava3.internal.operators.single.e((io.reactivex.rxjava3.core.p) withId.invoke(((QuestionDetailSetUpState.WithId) questionDetailSetUpState).a), new com.quizlet.eventlogger.e(this, 2), 1);
        Intrinsics.checkNotNullExpressionValue(eVar, "doFinally(...)");
        final int i2 = 1;
        final int i3 = 2;
        io.reactivex.rxjava3.internal.observers.e eVarB = B7.b(eVar, new Function1(this) { // from class: com.quizlet.explanations.questiondetail.viewmodel.a
            public final /* synthetic */ f b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                switch (i2) {
                    case 0:
                        String id = (String) obj;
                        Intrinsics.checkNotNullParameter(id, "id");
                        f fVar = this.b;
                        com.quizlet.data.repository.qclass.c cVar = fVar.d;
                        cVar.getClass();
                        Intrinsics.checkNotNullParameter(id, "id");
                        r stopToken = fVar.c;
                        Intrinsics.checkNotNullParameter(stopToken, "stopToken");
                        return ((androidx.work.impl.model.c) cVar.c).c(stopToken, new h(22, cVar, id));
                    case 1:
                        Throwable error = (Throwable) obj;
                        Intrinsics.checkNotNullParameter(error, "error");
                        f fVar2 = this.b;
                        QuestionDetailSetUpState questionDetailSetUpState2 = fVar2.m;
                        Z withId2 = new Z(26);
                        questionDetailSetUpState2.getClass();
                        Intrinsics.checkNotNullParameter(withId2, "withId");
                        if (!(questionDetailSetUpState2 instanceof QuestionDetailSetUpState.WithId)) {
                            throw new NoWhenBranchMatchedException();
                        }
                        Object objInvoke = withId2.invoke(((QuestionDetailSetUpState.WithId) questionDetailSetUpState2).a);
                        boolean z = error instanceof NoSuchElementException;
                        Y y = fVar2.v;
                        if (z) {
                            timber.log.c.a.i(error, "Question for (" + objInvoke + ") does not exist", new Object[0]);
                            y.j(com.quizlet.uicommon.ui.states.a.c);
                        } else {
                            y.j(com.quizlet.uicommon.ui.states.a.b);
                        }
                        return Unit.a;
                    default:
                        C4151n1 it2 = (C4151n1) obj;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        f fVar3 = this.b;
                        String str = fVar3.n;
                        androidx.work.impl.model.c cVar2 = fVar3.i;
                        io.reactivex.rxjava3.internal.observers.e eVarI = io.reactivex.rxjava3.core.p.o(cVar2.r(), cVar2.t(), fVar3.l.y(cVar2), b.a).i(new c(it2, fVar3, str), io.reactivex.rxjava3.internal.functions.d.e);
                        Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
                        Intrinsics.checkNotNullParameter(eVarI, "<this>");
                        fVar3.A(eVarI);
                        return Unit.a;
                }
            }
        }, new Function1(this) { // from class: com.quizlet.explanations.questiondetail.viewmodel.a
            public final /* synthetic */ f b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                switch (i3) {
                    case 0:
                        String id = (String) obj;
                        Intrinsics.checkNotNullParameter(id, "id");
                        f fVar = this.b;
                        com.quizlet.data.repository.qclass.c cVar = fVar.d;
                        cVar.getClass();
                        Intrinsics.checkNotNullParameter(id, "id");
                        r stopToken = fVar.c;
                        Intrinsics.checkNotNullParameter(stopToken, "stopToken");
                        return ((androidx.work.impl.model.c) cVar.c).c(stopToken, new h(22, cVar, id));
                    case 1:
                        Throwable error = (Throwable) obj;
                        Intrinsics.checkNotNullParameter(error, "error");
                        f fVar2 = this.b;
                        QuestionDetailSetUpState questionDetailSetUpState2 = fVar2.m;
                        Z withId2 = new Z(26);
                        questionDetailSetUpState2.getClass();
                        Intrinsics.checkNotNullParameter(withId2, "withId");
                        if (!(questionDetailSetUpState2 instanceof QuestionDetailSetUpState.WithId)) {
                            throw new NoWhenBranchMatchedException();
                        }
                        Object objInvoke = withId2.invoke(((QuestionDetailSetUpState.WithId) questionDetailSetUpState2).a);
                        boolean z = error instanceof NoSuchElementException;
                        Y y = fVar2.v;
                        if (z) {
                            timber.log.c.a.i(error, "Question for (" + objInvoke + ") does not exist", new Object[0]);
                            y.j(com.quizlet.uicommon.ui.states.a.c);
                        } else {
                            y.j(com.quizlet.uicommon.ui.states.a.b);
                        }
                        return Unit.a;
                    default:
                        C4151n1 it2 = (C4151n1) obj;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        f fVar3 = this.b;
                        String str = fVar3.n;
                        androidx.work.impl.model.c cVar2 = fVar3.i;
                        io.reactivex.rxjava3.internal.observers.e eVarI = io.reactivex.rxjava3.core.p.o(cVar2.r(), cVar2.t(), fVar3.l.y(cVar2), b.a).i(new c(it2, fVar3, str), io.reactivex.rxjava3.internal.functions.d.e);
                        Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
                        Intrinsics.checkNotNullParameter(eVarI, "<this>");
                        fVar3.A(eVarI);
                        return Unit.a;
                }
            }
        });
        Intrinsics.checkNotNullParameter(eVarB, "<this>");
        A(eVarB);
    }

    public final void C() {
        h7 toggleState;
        com.quizlet.baserecyclerview.a fVar;
        h7 toggleState2;
        Y y = this.p;
        List<g> list = (List) y.d();
        if (list != null) {
            ArrayList arrayList = new ArrayList(C.q(list, 10));
            for (g gVar : list) {
                boolean z = gVar instanceof com.quizlet.explanations.questiondetail.recyclerview.e;
                h7 h7Var = m.a;
                h7 h7Var2 = l.a;
                if (z) {
                    com.quizlet.explanations.questiondetail.recyclerview.e eVar = (com.quizlet.explanations.questiondetail.recyclerview.e) gVar;
                    h7 h7Var3 = eVar.c;
                    if (h7Var3 instanceof m) {
                        toggleState2 = h7Var2;
                    } else {
                        if (!(h7Var3 instanceof l)) {
                            throw new NoWhenBranchMatchedException();
                        }
                        toggleState2 = h7Var;
                    }
                    Intrinsics.checkNotNullParameter(toggleState2, "toggleState");
                    Function0 onToggleClick = eVar.h;
                    Intrinsics.checkNotNullParameter(onToggleClick, "onToggleClick");
                    Function1 onImageLongClick = eVar.i;
                    Intrinsics.checkNotNullParameter(onImageLongClick, "onImageLongClick");
                    fVar = new com.quizlet.explanations.questiondetail.recyclerview.e(eVar.b, toggleState2, eVar.d, eVar.e, eVar.f, eVar.g, onToggleClick, onImageLongClick);
                } else {
                    Intrinsics.e(gVar, "null cannot be cast to non-null type com.quizlet.explanations.questiondetail.recyclerview.QuestionDetailPrompt.LoggedOut");
                    com.quizlet.explanations.questiondetail.recyclerview.f fVar2 = (com.quizlet.explanations.questiondetail.recyclerview.f) gVar;
                    h7 h7Var4 = fVar2.c;
                    if (h7Var4 instanceof m) {
                        toggleState = h7Var2;
                    } else {
                        if (!(h7Var4 instanceof l)) {
                            throw new NoWhenBranchMatchedException();
                        }
                        toggleState = h7Var;
                    }
                    Intrinsics.checkNotNullParameter(toggleState, "toggleState");
                    Function0 onToggleClick2 = fVar2.h;
                    Intrinsics.checkNotNullParameter(onToggleClick2, "onToggleClick");
                    Function1 onImageLongClick2 = fVar2.i;
                    Intrinsics.checkNotNullParameter(onImageLongClick2, "onImageLongClick");
                    fVar = new com.quizlet.explanations.questiondetail.recyclerview.f(fVar2.b, toggleState, fVar2.d, fVar2.e, fVar2.f, fVar2.g, onToggleClick2, onImageLongClick2);
                }
                arrayList.add(fVar);
            }
            y.j(arrayList);
        }
    }
}

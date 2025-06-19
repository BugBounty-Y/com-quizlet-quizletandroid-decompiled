package com.quizlet.explanations.textbook.exercisedetail.viewmodel;

import androidx.lifecycle.X;
import androidx.lifecycle.Y;
import androidx.lifecycle.u0;
import com.braze.communication.k;
import com.google.android.gms.internal.mlkit_vision_barcode.B7;
import com.google.android.gms.internal.mlkit_vision_barcode.C6;
import com.google.firebase.messaging.p;
import com.quizlet.data.model.Exercise;
import com.quizlet.data.model.ExerciseDetails;
import com.quizlet.data.model.Textbook;
import com.quizlet.eventlogger.features.explanations.ExplanationsLogger;
import com.quizlet.eventlogger.features.explanations.d;
import com.quizlet.eventlogger.features.folder.FolderLogger;
import com.quizlet.eventlogger.model.ExplanationsEventLog;
import com.quizlet.explanations.solution.data.f;
import com.quizlet.explanations.solution.data.j;
import com.quizlet.explanations.textbook.exercisedetail.data.ExerciseDetailSetupState;
import com.quizlet.explanations.textbook.exercisedetail.recyclerview.footer.h;
import io.reactivex.rxjava3.internal.observers.e;
import io.reactivex.rxjava3.subjects.r;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import kotlin.Metadata;
import kotlin.collections.A;
import kotlin.collections.B;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class c extends com.quizlet.viewmodel.a {
    public final com.quizlet.data.interactor.school.b d;
    public final ExplanationsLogger e;
    public final androidx.work.impl.model.c f;
    public final com.quizlet.data.repository.searchexplanations.c g;
    public final com.quizlet.data.repository.folderset.c h;
    public final com.quizlet.time.b i;
    public final p j;
    public ExerciseDetailSetupState k;
    public final Y l;
    public final Y m;
    public final X n;
    public final X o;
    public final X p;
    public final X q;
    public final X r;
    public final Y s;
    public ExerciseDetails t;
    public com.quizlet.data.model.X u;

    public c(com.quizlet.data.interactor.school.b getExerciseDetailsUseCase, ExplanationsLogger explanationsLogger, androidx.work.impl.model.c userProperties, com.quizlet.data.repository.searchexplanations.c shareExplanationsHelper, com.quizlet.data.repository.folderset.c saveMyRecentExplanationItemUseCase, p blurringPaywallSolutionsFeature, FolderLogger folderEventLogger) {
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        Intrinsics.checkNotNullParameter(getExerciseDetailsUseCase, "getExerciseDetailsUseCase");
        Intrinsics.checkNotNullParameter(explanationsLogger, "explanationsLogger");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(shareExplanationsHelper, "shareExplanationsHelper");
        Intrinsics.checkNotNullParameter(saveMyRecentExplanationItemUseCase, "saveMyRecentExplanationItemUseCase");
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
        Intrinsics.checkNotNullParameter(blurringPaywallSolutionsFeature, "blurringPaywallSolutionsFeature");
        Intrinsics.checkNotNullParameter(folderEventLogger, "folderEventLogger");
        this.d = getExerciseDetailsUseCase;
        this.e = explanationsLogger;
        this.f = userProperties;
        this.g = shareExplanationsHelper;
        this.h = saveMyRecentExplanationItemUseCase;
        this.i = timeProvider;
        this.j = blurringPaywallSolutionsFeature;
        Y y = new Y();
        this.l = y;
        Y y2 = new Y(Boolean.FALSE);
        this.m = y2;
        this.n = C6.a(B.j(y2, y), new b(this, 0));
        this.o = C6.a(B.j(y2, y), new b(this, 1));
        this.p = new X(1);
        this.q = new X(1);
        this.r = new X(1);
        this.s = new Y();
        folderEventLogger.setScreenName("expert_solutions_exercise");
    }

    public static final void B(c cVar, Throwable th) {
        cVar.getClass();
        boolean z = th instanceof NoSuchElementException;
        Y y = cVar.s;
        if (!z) {
            y.j(com.quizlet.uicommon.ui.states.a.b);
            return;
        }
        timber.log.a aVar = timber.log.c.a;
        ExerciseDetailSetupState exerciseDetailSetupState = cVar.k;
        if (exerciseDetailSetupState == null) {
            Intrinsics.m("setupState");
            throw null;
        }
        aVar.i(th, android.support.v4.media.session.a.B("Exercise with id (", exerciseDetailSetupState.a(), ") does not exist"), new Object[0]);
        y.j(com.quizlet.uicommon.ui.states.a.c);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static void C(c cVar, ExerciseDetails exerciseDetails, j jVar, boolean z, com.quizlet.data.model.X x, int i) throws Throwable {
        c cVar2;
        K k;
        Throwable th;
        com.quizlet.explanations.textbook.exercisedetail.recyclerview.footer.b bVar;
        com.quizlet.explanations.textbook.exercisedetail.recyclerview.footer.b bVar2;
        boolean z2 = (i & 4) == 0;
        boolean z3 = (i & 8) != 0 ? false : z;
        cVar.getClass();
        if (jVar instanceof f) {
            List list = exerciseDetails.l;
            ArrayList arrayList = new ArrayList();
            if (list.isEmpty()) {
                cVar2 = cVar;
                th = null;
            } else {
                if (list.isEmpty()) {
                    throw new IllegalStateException("Next Exercises must not be empty");
                }
                Exercise exercise = (Exercise) list.get(0);
                th = null;
                com.quizlet.explanations.solution.fragments.b onClick = new com.quizlet.explanations.solution.fragments.b(1, cVar, c.class, "onExerciseClick", "onExerciseClick(Ljava/lang/String;)V", 0, 17);
                Intrinsics.checkNotNullParameter(exercise, "<this>");
                Intrinsics.checkNotNullParameter(onClick, "onClick");
                com.quizlet.explanations.textbook.exercisedetail.recyclerview.footer.b bVar3 = new com.quizlet.explanations.textbook.exercisedetail.recyclerview.footer.b(exercise.b, exercise.c, onClick);
                if (list.size() >= 2) {
                    Exercise exercise2 = (Exercise) list.get(1);
                    bVar = bVar3;
                    cVar2 = cVar;
                    com.quizlet.explanations.solution.fragments.b onClick2 = new com.quizlet.explanations.solution.fragments.b(1, cVar2, c.class, "onExerciseClick", "onExerciseClick(Ljava/lang/String;)V", 0, 18);
                    Intrinsics.checkNotNullParameter(exercise2, "<this>");
                    Intrinsics.checkNotNullParameter(onClick2, "onClick");
                    bVar2 = new com.quizlet.explanations.textbook.exercisedetail.recyclerview.footer.b(exercise2.b, exercise2.c, onClick2);
                } else {
                    bVar = bVar3;
                    cVar2 = cVar;
                    bVar2 = null;
                }
                arrayList.add(new h(bVar, bVar2));
            }
            if (cVar2.k == null) {
                Intrinsics.m("setupState");
                throw th;
            }
            k onDeepLink = new k(3, arrayList);
            Intrinsics.checkNotNullParameter(onDeepLink, "onDeepLink");
            k = arrayList;
        } else {
            cVar2 = cVar;
            k = K.a;
        }
        K k2 = k;
        com.quizlet.data.model.X x2 = cVar2.u;
        if (x2 != null) {
            ExplanationsLogger.EventData.Metering eventData = new ExplanationsLogger.EventData.Metering(exerciseDetails.b, 15, x2.d, x2.b);
            ExplanationsLogger.MeteringPlacement placement = ExplanationsLogger.MeteringPlacement.b;
            ExplanationsLogger explanationsLogger = cVar2.e;
            explanationsLogger.getClass();
            Intrinsics.checkNotNullParameter(eventData, "eventData");
            Intrinsics.checkNotNullParameter(placement, "placement");
            ExplanationsEventLog.Companion companion = ExplanationsEventLog.b;
            d dVar = new d(explanationsLogger, eventData, placement, 1);
            companion.getClass();
            explanationsLogger.a(ExplanationsEventLog.Companion.a("metered_explanations_pill_view", dVar));
        }
        Y y = cVar2.l;
        boolean zEquals = jVar.equals(com.quizlet.explanations.solution.data.a.a);
        Intrinsics.checkNotNullParameter(exerciseDetails, "<this>");
        y.j(new com.quizlet.explanations.textbook.exercisedetail.data.d(A.b(z2 ? new com.quizlet.explanations.textbook.exercisedetail.recyclerview.header.c(exerciseDetails.c, exerciseDetails.d, exerciseDetails.f, exerciseDetails.e, exerciseDetails.i, exerciseDetails.j.f, z3, x, zEquals) : new com.quizlet.explanations.textbook.exercisedetail.recyclerview.header.b(exerciseDetails.c, exerciseDetails.d, exerciseDetails.f, exerciseDetails.e, exerciseDetails.i, exerciseDetails.j.f, z3, x, zEquals)), jVar, K.a, k2));
    }

    public final void D(String id) {
        Intrinsics.checkNotNullParameter(id, "id");
        ExerciseDetailSetupState exerciseDetailSetupState = this.k;
        if (exerciseDetailSetupState == null) {
            Intrinsics.m("setupState");
            throw null;
        }
        this.p.j(new com.quizlet.explanations.textbook.exercisedetail.data.a(id, exerciseDetailSetupState instanceof ExerciseDetailSetupState.DeepLink));
        ExerciseDetails exerciseDetails = this.t;
        if (exerciseDetails == null) {
            return;
        }
        Textbook textbook = exerciseDetails.j;
        ExplanationsLogger.EventData.Exercise eventData = new ExplanationsLogger.EventData.Exercise(textbook.a, textbook.b, exerciseDetails.b);
        ExplanationsLogger explanationsLogger = this.e;
        explanationsLogger.getClass();
        Intrinsics.checkNotNullParameter(eventData, "eventData");
        ExplanationsEventLog.Companion companion = ExplanationsEventLog.b;
        com.quizlet.eventlogger.features.explanations.b bVar = new com.quizlet.eventlogger.features.explanations.b(explanationsLogger, eventData, 0);
        companion.getClass();
        explanationsLogger.a(ExplanationsEventLog.Companion.a("explanations_exercise_next_up_tapped", bVar));
    }

    public final void E(ExerciseDetailSetupState exerciseDetailSetupState, String screenName) {
        Intrinsics.checkNotNullParameter(exerciseDetailSetupState, "exerciseDetailSetupState");
        Intrinsics.checkNotNullParameter(screenName, "screenName");
        this.k = exerciseDetailSetupState;
        String id = exerciseDetailSetupState.a();
        com.quizlet.data.interactor.school.b bVar = this.d;
        bVar.getClass();
        Intrinsics.checkNotNullParameter(id, "id");
        r stopToken = this.c;
        Intrinsics.checkNotNullParameter(stopToken, "stopToken");
        e eVarB = B7.b(((androidx.work.impl.model.c) bVar.c).c(stopToken, new com.braze.triggers.managers.h(20, bVar, id)), new com.quizlet.explanations.solution.fragments.b(1, this, c.class, "handleError", "handleError(Ljava/lang/Throwable;)V", 0, 20), new u0(16, this, screenName));
        Intrinsics.checkNotNullParameter(eVarB, "<this>");
        A(eVarB);
    }
}

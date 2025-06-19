package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel;

import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3520q4;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.eventlogger.features.learn.LearnEventAction;
import com.quizlet.eventlogger.features.learn.LearnEventLog;
import com.quizlet.eventlogger.features.metering.StudyModeMeteringEventLogger;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.generated.enums.G1;
import com.quizlet.learn.data.LearnRoundSummaryData;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.q;
import com.quizlet.studiablemodels.AssistantCheckpointProgressState;
import com.quizlet.studiablemodels.StudiableMeteringData;
import io.reactivex.rxjava3.internal.operators.observable.C4885d;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.C4933y;
import kotlin.collections.K;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;
import kotlinx.coroutines.y0;

@Metadata
/* loaded from: classes3.dex */
public final class i extends com.quizlet.viewmodel.b implements b {
    public final com.quizlet.remote.model.notes.e c;
    public final com.quizlet.infra.legacysyncengine.managers.d d;
    public final com.quizlet.learn.logging.a e;
    public final StudyModeMeteringEventLogger f;
    public final com.quizlet.quizletandroid.managers.audio.h g;
    public final com.quizlet.features.infra.ui.feedback.sound.soundeffect.e h;
    public final s0 i;
    public final d0 j;
    public final LearnRoundSummaryData k;
    public final boolean l;
    public final StudiableMeteringData m;
    public final StudyableModelData n;
    public y0 o;

    public i(m0 savedStateHandle, com.quizlet.remote.model.notes.e dataManager, com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager, com.quizlet.learn.logging.a eventLogger, StudyModeMeteringEventLogger meteringLogger, com.quizlet.quizletandroid.managers.audio.h audioManager, com.quizlet.features.infra.ui.feedback.sound.soundeffect.e soundEffectPlayer) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(dataManager, "dataManager");
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        Intrinsics.checkNotNullParameter(meteringLogger, "meteringLogger");
        Intrinsics.checkNotNullParameter(audioManager, "audioManager");
        Intrinsics.checkNotNullParameter(soundEffectPlayer, "soundEffectPlayer");
        this.c = dataManager;
        this.d = loggedInUserManager;
        this.e = eventLogger;
        this.f = meteringLogger;
        this.g = audioManager;
        this.h = soundEffectPlayer;
        this.i = e0.c(com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.o.a);
        this.j = e0.b(0, 1, null, 5);
        Object objA = savedStateHandle.a("KEY_LEARN_ROUND_SUMMARY_DATA");
        if (objA == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        LearnRoundSummaryData learnRoundSummaryData = (LearnRoundSummaryData) objA;
        this.k = learnRoundSummaryData;
        Object objA2 = savedStateHandle.a("KEY_LEARN_ROUND_SUMMARY_FOCUSED_LEARN_RESULTS");
        if (objA2 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.l = ((Boolean) objA2).booleanValue();
        this.m = (StudiableMeteringData) savedStateHandle.a("KEY_LEARN_ROUND_SUMMARY_METERING_DATA");
        this.n = learnRoundSummaryData.f();
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object B(com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.i r6, java.util.List r7, long r8, kotlin.coroutines.jvm.internal.c r10) throws java.lang.Throwable {
        /*
            boolean r0 = r10 instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.g
            if (r0 == 0) goto L13
            r0 = r10
            com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.g r0 = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.g) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.g r0 = new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.g
            r0.<init>(r6, r10)
        L18:
            java.lang.Object r10 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 0
            r4 = 1
            if (r2 == 0) goto L38
            if (r2 != r4) goto L30
            long r8 = r0.l
            java.util.Iterator r6 = r0.k
            com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.i r7 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r10)     // Catch: java.lang.Throwable -> L2e
            goto L46
        L2e:
            r6 = move-exception
            goto L7a
        L30:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            java.util.ArrayList r7 = kotlin.collections.CollectionsKt.J(r7)     // Catch: java.lang.Throwable -> L78
            java.util.Iterator r7 = r7.iterator()     // Catch: java.lang.Throwable -> L78
            r5 = r7
            r7 = r6
            r6 = r5
        L46:
            boolean r10 = r6.hasNext()     // Catch: java.lang.Throwable -> L2e
            if (r10 == 0) goto L6e
            java.lang.Object r10 = r6.next()     // Catch: java.lang.Throwable -> L2e
            java.lang.String r10 = (java.lang.String) r10     // Catch: java.lang.Throwable -> L2e
            com.quizlet.quizletandroid.managers.audio.h r2 = r7.g     // Catch: java.lang.Throwable -> L2e
            r0.j = r7     // Catch: java.lang.Throwable -> L2e
            r0.k = r6     // Catch: java.lang.Throwable -> L2e
            r0.l = r8     // Catch: java.lang.Throwable -> L2e
            r0.o = r4     // Catch: java.lang.Throwable -> L2e
            io.reactivex.rxjava3.internal.operators.completable.a r10 = r2.a(r10)     // Catch: java.lang.Throwable -> L2e
            java.lang.Object r10 = com.google.android.gms.internal.mlkit_vision_camera.I1.a(r10, r0)     // Catch: java.lang.Throwable -> L2e
            kotlin.coroutines.intrinsics.a r2 = kotlin.coroutines.intrinsics.a.a     // Catch: java.lang.Throwable -> L2e
            if (r10 != r2) goto L69
            goto L6b
        L69:
            kotlin.Unit r10 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L2e
        L6b:
            if (r10 != r1) goto L46
            return r1
        L6e:
            r7.F(r8, r3)
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        L74:
            r5 = r7
            r7 = r6
            r6 = r5
            goto L7a
        L78:
            r7 = move-exception
            goto L74
        L7a:
            r7.F(r8, r3)
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.i.B(com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.i, java.util.List, long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final boolean C() {
        return this.n.getStudyableType() == G1.SET;
    }

    public final com.quizlet.learn.ui.g D() {
        com.quizlet.learn.ui.g gVar = null;
        StudiableMeteringData studiableMeteringData = this.m;
        Integer num = studiableMeteringData != null ? studiableMeteringData.e : null;
        if (num != null) {
            if (studiableMeteringData != null) {
                this.f.d(this.n.k(), this.k.d(), studiableMeteringData);
            }
            DBUser dBUser = this.d.r;
            com.quizlet.ui.states.a aVar = (dBUser == null || dBUser.getSelfIdentifiedUserType() != 1) ? com.quizlet.ui.states.a.c : com.quizlet.ui.states.a.d;
            int iIntValue = num.intValue();
            Object[] args = {num};
            Intrinsics.checkNotNullParameter(args, "args");
            com.quizlet.qutils.string.d dVar = new com.quizlet.qutils.string.d(R.plurals.learn_metering_upsell_rounds_remaining_prompt, iIntValue, C4933y.P(args));
            Object[] args2 = new Object[0];
            Intrinsics.checkNotNullParameter(args2, "args");
            gVar = new com.quizlet.learn.ui.g(aVar, dVar, new com.quizlet.qutils.string.f(R.string.learn_metering_upsell_description, C4933y.P(args2)));
        }
        return gVar;
    }

    public final void E(com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.f event) {
        Intrinsics.checkNotNullParameter(event, "event");
        boolean zB = Intrinsics.b(event, com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.a.a);
        d0 d0Var = this.j;
        if (zB) {
            d0Var.h(com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.g.a);
            return;
        }
        boolean z = event instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.d;
        com.quizlet.learn.logging.a aVar = this.e;
        if (z) {
            com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.d dVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.d) event;
            long j = dVar.a;
            aVar.getClass();
            aVar.a(LearnEventLog.Companion.a(LearnEventLog.b, LearnEventAction.d, null, Long.valueOf(j), 26));
            boolean z2 = dVar.c;
            F(j, !z2);
            y0 y0Var = this.o;
            if (y0Var != null) {
                y0Var.j(null);
            }
            if (z2) {
                return;
            }
            this.o = E.A(p0.j(this), null, null, new e(this, dVar.b, j, null), 3);
            return;
        }
        if (!(event instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.e)) {
            if (!Intrinsics.b(event, com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.b.a)) {
                if (!Intrinsics.b(event, com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.c.a)) {
                    throw new NoWhenBranchMatchedException();
                }
                d0Var.h(com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.j.a);
                return;
            } else {
                StudiableMeteringData studiableMeteringData = this.m;
                if (studiableMeteringData != null) {
                    this.f.c(this.n.k(), this.k.d(), studiableMeteringData);
                    return;
                }
                return;
            }
        }
        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.e eVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.e) event;
        long j2 = eVar.a;
        aVar.getClass();
        aVar.a(LearnEventLog.Companion.a(LearnEventLog.b, LearnEventAction.g, null, Long.valueOf(j2), 26));
        com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.e;
        boolean z3 = eVar.b;
        com.quizlet.remote.model.notes.e eVar2 = this.c;
        if (z3) {
            K k = K.a;
            io.reactivex.rxjava3.subjects.d dVar2 = (io.reactivex.rxjava3.subjects.d) eVar2.f;
            dVar2.getClass();
            Objects.requireNonNull(k, "defaultItem is null");
            io.reactivex.rxjava3.internal.observers.e eVarI = new C4885d(dVar2, k, 1).i(new com.quizlet.learn.checkpoint.data.b(eVar2, j2, 0), gVar);
            Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
            Intrinsics.checkNotNullParameter(eVarI, "<this>");
            A(eVarI);
            return;
        }
        K k2 = K.a;
        io.reactivex.rxjava3.subjects.d dVar3 = (io.reactivex.rxjava3.subjects.d) eVar2.f;
        dVar3.getClass();
        Objects.requireNonNull(k2, "defaultItem is null");
        io.reactivex.rxjava3.internal.observers.e eVarI2 = new C4885d(dVar3, k2, 1).i(new com.quizlet.learn.checkpoint.data.b(eVar2, j2, 1), gVar);
        Intrinsics.checkNotNullExpressionValue(eVarI2, "subscribe(...)");
        Intrinsics.checkNotNullParameter(eVarI2, "<this>");
        A(eVarI2);
    }

    public final void F(long j, boolean z) {
        Object value;
        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.p pVar;
        ArrayList termList;
        AssistantCheckpointProgressState progressState;
        Object value2;
        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.m mVar;
        ArrayList termList2;
        AssistantCheckpointProgressState progressState2;
        List enabledQuestionTypes;
        com.quizlet.learn.checkpoint.data.c progressBarState;
        s0 s0Var = this.i;
        q qVar = (q) s0Var.getValue();
        String str = "progressBarState";
        if (qVar instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.m) {
            do {
                value2 = s0Var.getValue();
                mVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.m) qVar;
                termList2 = AbstractC3520q4.b(j, mVar.h, z);
                progressState2 = mVar.a;
                Intrinsics.checkNotNullParameter(progressState2, "progressState");
                enabledQuestionTypes = mVar.f;
                Intrinsics.checkNotNullParameter(enabledQuestionTypes, "enabledQuestionTypes");
                Intrinsics.checkNotNullParameter(termList2, "termList");
                progressBarState = mVar.j;
                Intrinsics.checkNotNullParameter(progressBarState, "progressBarState");
            } while (!s0Var.k(value2, new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.m(progressState2, mVar.b, mVar.c, mVar.d, mVar.e, enabledQuestionTypes, mVar.g, termList2, mVar.i, progressBarState, mVar.k)));
            return;
        }
        if (!(qVar instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.n)) {
            if (!(qVar instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.p)) {
                if (!Intrinsics.b(qVar, com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.o.a)) {
                    throw new NoWhenBranchMatchedException();
                }
                timber.log.c.a.d("Not able to play audio during loading", new Object[0]);
                return;
            }
            do {
                value = s0Var.getValue();
                pVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.p) qVar;
                termList = AbstractC3520q4.b(j, pVar.b, z);
                progressState = pVar.a;
                Intrinsics.checkNotNullParameter(progressState, "progressState");
                Intrinsics.checkNotNullParameter(termList, "termList");
            } while (!s0Var.k(value, new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.p(progressState, termList, pVar.c, pVar.d)));
            return;
        }
        while (true) {
            Object value3 = s0Var.getValue();
            com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.n nVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.n) qVar;
            ArrayList termList3 = AbstractC3520q4.b(j, nVar.l, z);
            AssistantCheckpointProgressState progressState3 = nVar.a;
            Intrinsics.checkNotNullParameter(progressState3, "progressState");
            com.quizlet.qutils.string.g header = nVar.d;
            Intrinsics.checkNotNullParameter(header, "header");
            com.quizlet.qutils.string.g message = nVar.e;
            Intrinsics.checkNotNullParameter(message, "message");
            com.quizlet.qutils.string.g primaryCtaText = nVar.f;
            Intrinsics.checkNotNullParameter(primaryCtaText, "primaryCtaText");
            com.quizlet.qutils.string.g secondaryCtaText = nVar.g;
            Intrinsics.checkNotNullParameter(secondaryCtaText, "secondaryCtaText");
            Function0 primaryCtaClick = nVar.j;
            Intrinsics.checkNotNullParameter(primaryCtaClick, "primaryCtaClick");
            Function0 secondaryCtaClick = nVar.k;
            Intrinsics.checkNotNullParameter(secondaryCtaClick, "secondaryCtaClick");
            Intrinsics.checkNotNullParameter(termList3, "termList");
            com.quizlet.learn.checkpoint.data.c cVar = nVar.n;
            Intrinsics.checkNotNullParameter(cVar, str);
            String str2 = str;
            if (s0Var.k(value3, new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.n(progressState3, nVar.b, nVar.c, header, message, primaryCtaText, secondaryCtaText, nVar.h, nVar.i, primaryCtaClick, secondaryCtaClick, termList3, nVar.m, cVar, nVar.o))) {
                return;
            } else {
                str = str2;
            }
        }
    }
}

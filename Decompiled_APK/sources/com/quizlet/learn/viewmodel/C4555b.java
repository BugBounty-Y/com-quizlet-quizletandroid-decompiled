package com.quizlet.learn.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.eventlogger.model.LearnPostCompletionEventLog;
import com.quizlet.generated.enums.G1;
import com.quizlet.learn.data.AbstractC4540e;
import com.quizlet.learn.data.C4538c;
import com.quizlet.learn.data.C4539d;
import com.quizlet.quizletandroid.R;
import com.quizlet.studiablemodels.AssistantCheckpointProgressState;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.s0;

/* renamed from: com.quizlet.learn.viewmodel.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4555b extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C4556c k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4555b(C4556c c4556c, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c4556c;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4555b(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4555b) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        AbstractC4540e c4538c;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            C4556c c4556c = this.k;
            com.quizlet.learn.logging.d dVar = c4556c.d;
            AssistantCheckpointProgressState assistantCheckpointProgressState = c4556c.g;
            String progressState = assistantCheckpointProgressState.a;
            dVar.getClass();
            Intrinsics.checkNotNullParameter(progressState, "progressState");
            LearnPostCompletionEventLog.Companion companion = LearnPostCompletionEventLog.b;
            com.quizlet.features.notes.logging.c cVar = new com.quizlet.features.notes.logging.c(progressState, 28);
            companion.getClass();
            dVar.a.l(LearnPostCompletionEventLog.Companion.a("learn_ending_screen_seen", cVar));
            boolean z = c4556c.e.getStudyableType() == G1.SET;
            int iOrdinal = assistantCheckpointProgressState.ordinal();
            if (iOrdinal == 2) {
                c4538c = new C4538c(z ? Integer.valueOf(R.string.learn_end_take_test_button) : null, new com.quizlet.learn.ads.g(0, c4556c, C4556c.class, "onPracticeMoreClicked", "onPracticeMoreClicked()V", 0, 1), new com.quizlet.learn.ads.g(0, c4556c, C4556c.class, "onTakeTestClicked", "onTakeTestClicked()V", 0, 2));
            } else {
                if (iOrdinal != 3) {
                    throw new IllegalStateException("Invalid AssistantCheckpointProgressState: " + assistantCheckpointProgressState);
                }
                c4538c = new C4539d(z ? Integer.valueOf(R.string.learn_end_take_test_button) : null, new com.quizlet.learn.ads.g(0, c4556c, C4556c.class, "onTakeTestClicked", "onTakeTestClicked()V", 0, 3), new com.quizlet.learn.ads.g(0, c4556c, C4556c.class, "onPracticeMoreClicked", "onPracticeMoreClicked()V", 0, 4));
            }
            com.quizlet.learn.data.y yVar = new com.quizlet.learn.data.y(c4538c, false, null);
            this.j = 1;
            s0 s0Var = c4556c.h;
            s0Var.getClass();
            s0Var.m(null, yVar);
            if (Unit.a == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}

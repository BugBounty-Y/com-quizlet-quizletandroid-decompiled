package com.quizlet.eventlogger.features.learnonboarding;

import assistantMode.enums.y;
import com.quizlet.data.model.C4161r0;
import com.quizlet.eventlogger.features.learnonboarding.LearnOnboardingEventLog;
import com.quizlet.eventlogger.features.study.StudyFunnelEventLogger;
import com.quizlet.eventlogger.model.AndroidEventLog;
import com.quizlet.eventlogger.model.AndroidEventPayload;
import com.quizlet.features.folders.data.E0;
import com.quizlet.features.folders.data.F0;
import com.quizlet.features.folders.data.G0;
import com.quizlet.features.folders.data.I0;
import com.quizlet.features.folders.data.J0;
import com.quizlet.features.folders.data.K0;
import com.quizlet.features.folders.logging.e;
import com.quizlet.features.infra.basestudy.manager.d;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.EnumC4519s1;
import com.quizlet.generated.enums.F;
import com.quizlet.quizletandroid.ui.startpage.nav2.Y;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ a(Y y, long j, F f) {
        this.a = 3;
        this.c = y;
        this.b = j;
        this.d = f;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        String str;
        switch (this.a) {
            case 0:
                LearnOnboardingEventLog.Payload createEvent = (LearnOnboardingEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setSetId(Long.valueOf(this.b));
                createEvent.setStudyModeType(Integer.valueOf(A1.WRITE.a()));
                com.quizlet.studiablemodels.assistantMode.a aVar = (com.quizlet.studiablemodels.assistantMode.a) this.c;
                if (aVar != null) {
                    createEvent.setGoal(Integer.valueOf(aVar.ordinal()));
                }
                y yVar = (y) this.d;
                if (yVar != null) {
                    createEvent.setKnowledgeLevel(Integer.valueOf(yVar.ordinal()));
                }
                return Unit.a;
            case 1:
                AndroidEventLog logAndroidEvent = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logAndroidEvent, "$this$logAndroidEvent");
                logAndroidEvent.getPayload().setFolderId(Long.valueOf(this.b));
                AndroidEventPayload payload = logAndroidEvent.getPayload();
                ((e) this.c).getClass();
                E0 e0 = E0.b;
                K0 k0 = (K0) this.d;
                if (Intrinsics.b(k0, e0) || Intrinsics.b(k0, F0.b) || Intrinsics.b(k0, G0.b)) {
                    str = "recent";
                } else {
                    if (!Intrinsics.b(k0, I0.b) && !Intrinsics.b(k0, J0.b)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    str = "alphabetical";
                }
                payload.setSortType(str);
                return Unit.a;
            case 2:
                AndroidEventLog logAndroidEvent2 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logAndroidEvent2, "$this$logAndroidEvent");
                logAndroidEvent2.getPayload().setFolderId(Long.valueOf(this.b));
                logAndroidEvent2.getPayload().setTagName((String) this.c);
                logAndroidEvent2.getPayload().setClickSource((String) this.d);
                return Unit.a;
            default:
                C4161r0 it2 = (C4161r0) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                d dVar = ((Y) this.c).j;
                dVar.getClass();
                F reason = (F) this.d;
                Intrinsics.checkNotNullParameter(reason, "reason");
                long j = this.b;
                com.quizlet.features.infra.basestudy.manager.c cVarC = dVar.c(j);
                if (cVarC != null) {
                    EnumC4519s1 enumC4519s1 = EnumC4519s1.REJECT;
                    com.quizlet.features.infra.basestudy.manager.b bVar = cVarC.b;
                    StudyFunnelEventLogger.a(dVar.a, enumC4519s1, Long.valueOf(j), 1, cVarC.a, bVar.d, bVar.e, bVar.f, bVar.g, reason, null, null, null, 3584);
                }
                return Unit.a;
        }
    }

    public /* synthetic */ a(Object obj, long j, Object obj2, int i) {
        this.a = i;
        this.b = j;
        this.c = obj;
        this.d = obj2;
    }
}

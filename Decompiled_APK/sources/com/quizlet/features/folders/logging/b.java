package com.quizlet.features.folders.logging;

import com.quizlet.eventlogger.model.AndroidEventLog;
import com.quizlet.eventlogger.model.AndroidEventPayload;
import com.quizlet.eventlogger.model.StudyFunnelEventLog;
import com.quizlet.generated.enums.y1;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ f b;

    public /* synthetic */ b(f fVar, int i) {
        this.a = i;
        this.b = fVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                AndroidEventLog logAndroidEvent = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logAndroidEvent, "$this$logAndroidEvent");
                AndroidEventPayload payload = logAndroidEvent.getPayload();
                f fVar = this.b;
                payload.setFolderId(Long.valueOf(fVar.a));
                logAndroidEvent.getPayload().setStudyMaterialId(fVar.b);
                AndroidEventPayload payload2 = logAndroidEvent.getPayload();
                y1 y1Var = fVar.c;
                payload2.setStudyMaterialType(y1Var != null ? Integer.valueOf(y1Var.b()) : null);
                logAndroidEvent.getPayload().setCourseRecommendation(Boolean.valueOf(fVar.d));
                logAndroidEvent.getPayload().setCoursePowered(Boolean.FALSE);
                break;
            default:
                StudyFunnelEventLog logAction = (StudyFunnelEventLog) obj;
                Intrinsics.checkNotNullParameter(logAction, "$this$logAction");
                StudyFunnelEventLog.Payload payload3 = logAction.getPayload();
                f fVar2 = this.b;
                payload3.setTag(fVar2.f);
                logAction.getPayload().setFolderId(Long.valueOf(fVar2.a));
                break;
        }
        return Unit.a;
    }
}

package com.quizlet.features.folders.logging;

import com.quizlet.eventlogger.model.AndroidEventLog;
import com.quizlet.eventlogger.model.StudyFunnelEventLog;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Long b;
    public final /* synthetic */ String c;

    public /* synthetic */ a(Long l, String str) {
        this.a = 3;
        this.c = str;
        this.b = l;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                AndroidEventLog logAndroidEvent = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logAndroidEvent, "$this$logAndroidEvent");
                logAndroidEvent.getPayload().setFolderId(this.b);
                logAndroidEvent.getPayload().setTagName(this.c);
                break;
            case 1:
                AndroidEventLog logAndroidEvent2 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logAndroidEvent2, "$this$logAndroidEvent");
                logAndroidEvent2.getPayload().setFolderId(this.b);
                logAndroidEvent2.getPayload().setTagName(this.c);
                break;
            case 2:
                AndroidEventLog logAndroidEvent3 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logAndroidEvent3, "$this$logAndroidEvent");
                logAndroidEvent3.getPayload().setFolderId(this.b);
                logAndroidEvent3.getPayload().setTagName(this.c);
                break;
            default:
                StudyFunnelEventLog ImpressionsPayload = (StudyFunnelEventLog) obj;
                Intrinsics.checkNotNullParameter(ImpressionsPayload, "$this$ImpressionsPayload");
                ImpressionsPayload.getPayload().setTag(this.c);
                ImpressionsPayload.getPayload().setFolderId(this.b);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ a(Long l, String str, int i) {
        this.a = i;
        this.b = l;
        this.c = str;
    }
}

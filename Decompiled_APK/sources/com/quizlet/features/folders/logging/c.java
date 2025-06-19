package com.quizlet.features.folders.logging;

import com.quizlet.eventlogger.model.AndroidEventLog;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;
    public final /* synthetic */ boolean c;

    public /* synthetic */ c(boolean z, long j, int i) {
        this.a = i;
        this.b = j;
        this.c = z;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        AndroidEventLog logAndroidEvent = (AndroidEventLog) obj;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(logAndroidEvent, "$this$logAndroidEvent");
                logAndroidEvent.getPayload().setFolderId(Long.valueOf(this.b));
                logAndroidEvent.getPayload().setCoursePowered(Boolean.valueOf(this.c));
                break;
            default:
                Intrinsics.checkNotNullParameter(logAndroidEvent, "$this$logAndroidEvent");
                logAndroidEvent.getPayload().setFolderId(Long.valueOf(this.b));
                logAndroidEvent.getPayload().setCoursePowered(Boolean.valueOf(this.c));
                break;
        }
        return Unit.a;
    }
}

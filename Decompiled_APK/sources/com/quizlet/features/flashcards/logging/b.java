package com.quizlet.features.flashcards.logging;

import assistantMode.enums.k;
import assistantMode.enums.m;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.model.QuestionEventLog;
import com.quizlet.generated.enums.A1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b {
    public final EventLogger a;

    public b(EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.a = eventLogger;
    }

    public static QuestionEventLog a(String str, String str2, String str3, c cVar, m mVar, m mVar2, Integer num, A1 a1, k kVar) {
        QuestionEventLog.Companion companion = QuestionEventLog.b;
        long j = cVar.a;
        return QuestionEventLog.Companion.b(companion, str3, str, str2, j < 0 ? null : Long.valueOf(j), j, 0, cVar.b, cVar.c, cVar.d, cVar.e, cVar.f, cVar.g, AbstractC3106b5.g(mVar2), AbstractC3106b5.g(mVar), num, null, null, null, a1, kVar, 419430400);
    }
}

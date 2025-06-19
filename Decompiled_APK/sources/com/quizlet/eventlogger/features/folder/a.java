package com.quizlet.eventlogger.features.folder;

import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.eventlogger.model.AndroidEventLog;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Long b;

    public /* synthetic */ a(int i, Long l) {
        this.a = i;
        this.b = l;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                AndroidEventLog logAndroidEvent = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logAndroidEvent, "$this$logAndroidEvent");
                logAndroidEvent.getPayload().setFolderId(this.b);
                return Unit.a;
            case 1:
                return Boolean.valueOf(((DBTerm) obj).getId() == this.b.longValue());
            default:
                return Boolean.valueOf(((DBTerm) obj).getId() == this.b.longValue());
        }
    }
}

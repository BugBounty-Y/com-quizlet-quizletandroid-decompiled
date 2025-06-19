package com.quizlet.quizletandroid.ui.group.classcontent.logging;

import com.quizlet.eventlogger.model.AndroidEventLog;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;
    public final /* synthetic */ long c;

    public /* synthetic */ a(long j, long j2, int i) {
        this.a = i;
        this.b = j;
        this.c = j2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        AndroidEventLog logUserActionAndroidEvent = (AndroidEventLog) obj;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent.setAction("removed_set_from_class");
                logUserActionAndroidEvent.setClassId(Long.valueOf(this.b));
                logUserActionAndroidEvent.setSetId(Long.valueOf(this.c));
                break;
            case 1:
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent.setAction("added_set_to_class");
                logUserActionAndroidEvent.setClassId(Long.valueOf(this.b));
                logUserActionAndroidEvent.setSetId(Long.valueOf(this.c));
                break;
            case 2:
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent.setAction("added_folder_to_class");
                logUserActionAndroidEvent.setClassId(Long.valueOf(this.b));
                logUserActionAndroidEvent.setFolderId(Long.valueOf(this.c));
                break;
            default:
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent.setAction("removed_folder_from_class");
                logUserActionAndroidEvent.setClassId(Long.valueOf(this.b));
                logUserActionAndroidEvent.setFolderId(Long.valueOf(this.c));
                break;
        }
        return Unit.a;
    }
}

package com.quizlet.assembly.compose.modals;

import androidx.compose.material3.G3;
import androidx.compose.runtime.C0776c;
import com.quizlet.eventlogger.features.autolaunch.AutoLaunchEventLog;
import com.quizlet.eventlogger.model.AndroidEventLog;
import com.quizlet.eventlogger.model.NotesEventLog;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class g implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ boolean b;

    public /* synthetic */ g(boolean z, int i) {
        this.a = i;
        this.b = z;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter((G3) obj, "it");
                return Boolean.valueOf(this.b);
            case 1:
                y it2 = (y) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                return new x(C0776c.z(it2), this.b);
            case 2:
                AutoLaunchEventLog.Payload createEvent = (AutoLaunchEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setWithinWaitSeconds(Boolean.valueOf(this.b));
                return Unit.a;
            case 3:
                AutoLaunchEventLog.Payload createEvent2 = (AutoLaunchEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent2, "$this$createEvent");
                createEvent2.setWaitSeconds(8L);
                createEvent2.setEnableAutoLaunch(Boolean.valueOf(this.b));
                return Unit.a;
            case 4:
                NotesEventLog.Payload createEvent3 = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent3, "$this$createEvent");
                createEvent3.setVisible(Boolean.valueOf(this.b));
                return Unit.a;
            case 5:
                AndroidEventLog logUserActionAndroidEvent = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent.setUserAction("share_set_dialog_shown");
                logUserActionAndroidEvent.setWhatsAppShareDisplayed(Boolean.valueOf(this.b));
                return Unit.a;
            default:
                com.quizlet.data.model.D createClassFolders = (com.quizlet.data.model.D) obj;
                Intrinsics.checkNotNullParameter(createClassFolders, "$this$createClassFolders");
                Boolean boolValueOf = Boolean.valueOf(this.b);
                return new com.quizlet.data.model.D(createClassFolders.a, createClassFolders.b, createClassFolders.c, createClassFolders.d, createClassFolders.e, boolValueOf, createClassFolders.g, createClassFolders.h, true);
        }
    }

    public /* synthetic */ g(boolean z, boolean z2) {
        this.a = 1;
        this.b = z;
    }
}

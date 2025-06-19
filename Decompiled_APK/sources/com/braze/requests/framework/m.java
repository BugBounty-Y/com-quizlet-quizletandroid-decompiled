package com.braze.requests.framework;

import androidx.compose.material3.AbstractC0621g1;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import com.quizlet.eventlogger.features.learnonboarding.LearnOnboardingEventLog;
import com.quizlet.eventlogger.model.AndroidEventLog;
import com.quizlet.eventlogger.model.LibraryEventLog;
import com.quizlet.eventlogger.model.UniversalUploadFlowEventLog;
import com.quizlet.features.achievements.ui.composables.z;
import com.quizlet.generated.enums.A1;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class m implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;

    public /* synthetic */ m(int i, long j) {
        this.a = i;
        this.b = j;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                return b.b(this.b, (h) obj);
            case 1:
                return g.b(this.b, (b) obj);
            case 2:
                LearnOnboardingEventLog.Payload createEvent = (LearnOnboardingEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setSetId(Long.valueOf(this.b));
                return Unit.a;
            case 3:
                LearnOnboardingEventLog.Payload createEvent2 = (LearnOnboardingEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent2, "$this$createEvent");
                createEvent2.setSetId(Long.valueOf(this.b));
                createEvent2.setStudyModeType(Integer.valueOf(A1.WRITE.a()));
                return Unit.a;
            case 4:
                AndroidEventLog logUserActionAndroidEvent = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent.setUserAction("meter_overriden_for_teacher_set");
                logUserActionAndroidEvent.setSetId(Long.valueOf(this.b));
                return Unit.a;
            case 5:
                androidx.compose.foundation.lazy.g LazyColumn = (androidx.compose.foundation.lazy.g) obj;
                Intrinsics.checkNotNullParameter(LazyColumn, "$this$LazyColumn");
                LazyColumn.q(5, null, androidx.compose.foundation.lazy.o.c, new androidx.compose.runtime.internal.d(true, 1145268849, new z(1, this.b)));
                return Unit.a;
            case 6:
                AndroidEventLog logAndroidEvent = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logAndroidEvent, "$this$logAndroidEvent");
                logAndroidEvent.getPayload().setFolderId(Long.valueOf(this.b));
                return Unit.a;
            case 7:
                AndroidEventLog logAndroidEvent2 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logAndroidEvent2, "$this$logAndroidEvent");
                logAndroidEvent2.getPayload().setFolderId(Long.valueOf(this.b));
                return Unit.a;
            case 8:
                AndroidEventLog logAndroidEvent3 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logAndroidEvent3, "$this$logAndroidEvent");
                logAndroidEvent3.getPayload().setFolderId(Long.valueOf(this.b));
                logAndroidEvent3.getPayload().setClickSource("add_tag_modal");
                return Unit.a;
            case 9:
                AndroidEventLog logAndroidEvent4 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logAndroidEvent4, "$this$logAndroidEvent");
                logAndroidEvent4.getPayload().setFolderId(Long.valueOf(this.b));
                return Unit.a;
            case 10:
                AndroidEventLog logAndroidEvent5 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logAndroidEvent5, "$this$logAndroidEvent");
                logAndroidEvent5.getPayload().setFolderId(Long.valueOf(this.b));
                return Unit.a;
            case 11:
                AndroidEventLog logAndroidEvent6 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logAndroidEvent6, "$this$logAndroidEvent");
                logAndroidEvent6.getPayload().setFolderId(Long.valueOf(this.b));
                return Unit.a;
            case 12:
                AndroidEventLog logAndroidEvent7 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logAndroidEvent7, "$this$logAndroidEvent");
                logAndroidEvent7.getPayload().setFolderId(Long.valueOf(this.b));
                return Unit.a;
            case 13:
                AndroidEventLog logAndroidEvent8 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logAndroidEvent8, "$this$logAndroidEvent");
                logAndroidEvent8.getPayload().setFolderId(Long.valueOf(this.b));
                return Unit.a;
            case 14:
                AndroidEventLog logAndroidEvent9 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logAndroidEvent9, "$this$logAndroidEvent");
                logAndroidEvent9.getPayload().setFolderId(Long.valueOf(this.b));
                return Unit.a;
            case 15:
                androidx.compose.ui.graphics.drawscope.d Canvas = (androidx.compose.ui.graphics.drawscope.d) obj;
                Intrinsics.checkNotNullParameter(Canvas, "$this$Canvas");
                androidx.compose.ui.graphics.drawscope.d.V(Canvas, this.b, DefinitionKt.NO_Float_VALUE, 0L, null, 126);
                return Unit.a;
            case 16:
                androidx.compose.ui.graphics.drawscope.d Canvas2 = (androidx.compose.ui.graphics.drawscope.d) obj;
                Intrinsics.checkNotNullParameter(Canvas2, "$this$Canvas");
                androidx.compose.ui.graphics.drawscope.d.V(Canvas2, this.b, DefinitionKt.NO_Float_VALUE, 0L, new androidx.compose.ui.graphics.drawscope.h(1.0f, DefinitionKt.NO_Float_VALUE, 0, 0, 30), OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SHOW_BANNER_CALLED);
                return Unit.a;
            case 17:
                androidx.compose.ui.graphics.drawscope.d Canvas3 = (androidx.compose.ui.graphics.drawscope.d) obj;
                Intrinsics.checkNotNullParameter(Canvas3, "$this$Canvas");
                androidx.compose.ui.graphics.drawscope.d.V(Canvas3, this.b, 24.0f, 0L, new androidx.compose.ui.graphics.drawscope.h(6.0f, DefinitionKt.NO_Float_VALUE, 0, 0, 30), OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_BACKWARD_COMPATIBILITY);
                return Unit.a;
            case 18:
                AndroidEventLog logUserActionAndroidEvent2 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent2, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent2.setUserAction("tapped_subject_set");
                logUserActionAndroidEvent2.setMessage(String.valueOf(this.b));
                return Unit.a;
            case 19:
                androidx.compose.ui.graphics.drawscope.d drawBehind = (androidx.compose.ui.graphics.drawscope.d) obj;
                Intrinsics.checkNotNullParameter(drawBehind, "$this$drawBehind");
                float f = com.quizlet.ui.resources.designsystem.generated.j.g;
                float f2 = -drawBehind.c0(f);
                float f3 = AbstractC0621g1.a;
                drawBehind.C(this.b, Q4.c(f2, drawBehind.c0(f3)), Q4.c(-drawBehind.c0(f), androidx.compose.ui.geometry.e.b(drawBehind.g())), drawBehind.c0(f3), (496 & 16) != 0 ? 0 : 0);
                return Unit.a;
            case 20:
                UniversalUploadFlowEventLog.Payload createEvent3 = (UniversalUploadFlowEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent3, "$this$createEvent");
                createEvent3.setSetId(Long.valueOf(this.b));
                return Unit.a;
            case 21:
                LibraryEventLog.Payload createEvent4 = (LibraryEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent4, "$this$createEvent");
                createEvent4.setModelId(Long.valueOf(this.b));
                createEvent4.setModelType(3);
                createEvent4.setLocation("Library");
                createEvent4.setPlacement("folder_tab");
                return Unit.a;
            case EventType.WINDOW_STATE /* 22 */:
                LibraryEventLog.Payload createEvent5 = (LibraryEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent5, "$this$createEvent");
                createEvent5.setModelId(Long.valueOf(this.b));
                createEvent5.setModelType(4);
                createEvent5.setLocation("Library");
                createEvent5.setPlacement("class_tab");
                return Unit.a;
            case EventType.AUDIO /* 23 */:
                LibraryEventLog.Payload createEvent6 = (LibraryEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent6, "$this$createEvent");
                createEvent6.setModelId(Long.valueOf(this.b));
                createEvent6.setModelType(1);
                createEvent6.setLocation("Library");
                createEvent6.setPlacement("set_tab");
                return Unit.a;
            case EventType.VIDEO /* 24 */:
                AndroidEventLog logUserActionAndroidEvent3 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent3, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent3.setAction("tap_add_folder_to_class");
                logUserActionAndroidEvent3.setClassId(Long.valueOf(this.b));
                return Unit.a;
            case EventType.SUBS /* 25 */:
                AndroidEventLog logUserActionAndroidEvent4 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent4, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent4.setAction("tap_add_set_to_class");
                logUserActionAndroidEvent4.setClassId(Long.valueOf(this.b));
                logUserActionAndroidEvent4.setLocation("class_options");
                return Unit.a;
            case EventType.CDN /* 26 */:
                AndroidEventLog logUserActionAndroidEvent5 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent5, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent5.setAction("tap_add_set_to_class");
                logUserActionAndroidEvent5.setSetId(Long.valueOf(this.b));
                logUserActionAndroidEvent5.setLocation("set_options");
                return Unit.a;
            case 27:
                androidx.compose.ui.graphics.drawscope.d drawBehind2 = (androidx.compose.ui.graphics.drawscope.d) obj;
                Intrinsics.checkNotNullParameter(drawBehind2, "$this$drawBehind");
                androidx.compose.ui.graphics.drawscope.d.V(drawBehind2, this.b, 25.0f, 0L, null, 124);
                return Unit.a;
            default:
                return Long.valueOf(this.b);
        }
    }

    public /* synthetic */ m(long j) {
        this.a = 19;
        com.quizlet.ui.resources.designsystem.generated.j jVar = com.quizlet.ui.resources.designsystem.generated.j.d;
        this.b = j;
    }
}

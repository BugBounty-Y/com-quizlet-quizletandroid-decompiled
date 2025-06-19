package com.quizlet.features.flashcards;

import androidx.compose.material3.EnumC0630h4;
import androidx.navigation.C1290l;
import androidx.navigation.Y;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.eventlogger.model.NavigationEventLog;
import com.quizlet.features.folders.composables.AbstractC4247c;
import com.quizlet.features.folders.data.T;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.O1;
import com.quizlet.quizletandroid.R;
import com.quizlet.studiablemodels.StudiableAudio;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.flashcards.k, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C4237k implements Function1 {
    public final /* synthetic */ int a;

    public /* synthetic */ C4237k(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                ((Boolean) obj).booleanValue();
                return Unit.a;
            case 1:
                StudiableAudio it2 = (StudiableAudio) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                return Unit.a;
            case 2:
                androidx.navigation.L navOptions = (androidx.navigation.L) obj;
                Intrinsics.checkNotNullParameter(navOptions, "$this$navOptions");
                navOptions.b = true;
                return Unit.a;
            case 3:
                C1290l navArgument = (C1290l) obj;
                Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                navArgument.a.a = false;
                navArgument.b(androidx.navigation.S.b);
                navArgument.a(Integer.valueOf(A1.FLASHCARDS.a()));
                return Unit.a;
            case 4:
                timber.log.c.a.g("Error loading data: " + ((Throwable) obj), new Object[0]);
                return Unit.a;
            case 5:
                androidx.compose.foundation.lazy.g LazyColumn = (androidx.compose.foundation.lazy.g) obj;
                Intrinsics.checkNotNullParameter(LazyColumn, "$this$LazyColumn");
                androidx.compose.foundation.lazy.g.p(LazyColumn, null, AbstractC4247c.a, 3);
                LazyColumn.q(8, null, androidx.compose.foundation.lazy.o.c, AbstractC4247c.b);
                return Unit.a;
            case 6:
                Integer num = (Integer) obj;
                num.intValue();
                return num;
            case 7:
                EnumC0630h4 it3 = (EnumC0630h4) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                return Boolean.TRUE;
            case 8:
                T it4 = (T) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                return Unit.a;
            case 9:
                NavigationEventLog.Payload it5 = (NavigationEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(it5, "it");
                return Unit.a;
            case 10:
                com.quizlet.ui.models.content.listitem.o it6 = (com.quizlet.ui.models.content.listitem.o) obj;
                Intrinsics.checkNotNullParameter(it6, "it");
                return Unit.a;
            case 11:
                String it7 = (String) obj;
                Intrinsics.checkNotNullParameter(it7, "it");
                return Unit.a;
            case 12:
                return AbstractC3106b5.f((O1) obj);
            case 13:
                com.quizlet.ui.models.webpage.m it8 = (com.quizlet.ui.models.webpage.m) obj;
                Intrinsics.checkNotNullParameter(it8, "it");
                return Unit.a;
            case 14:
                ((Boolean) obj).booleanValue();
                return Unit.a;
            case 15:
                String it9 = (String) obj;
                Intrinsics.checkNotNullParameter(it9, "it");
                return Unit.a;
            case 16:
                String it10 = (String) obj;
                Intrinsics.checkNotNullParameter(it10, "it");
                return Unit.a;
            case 17:
                com.quizlet.features.infra.models.folders.c it11 = (com.quizlet.features.infra.models.folders.c) obj;
                Intrinsics.checkNotNullParameter(it11, "it");
                return Unit.a;
            case 18:
                com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.n it12 = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.n) obj;
                Intrinsics.checkNotNullParameter(it12, "it");
                return Unit.a;
            case 19:
                com.quizlet.features.infra.folder.menu.data.b it13 = (com.quizlet.features.infra.folder.menu.data.b) obj;
                Intrinsics.checkNotNullParameter(it13, "it");
                return Long.valueOf(it13.a);
            case 20:
                com.quizlet.features.infra.folder.menu.data.g it14 = (com.quizlet.features.infra.folder.menu.data.g) obj;
                Intrinsics.checkNotNullParameter(it14, "it");
                return Long.valueOf(it14.getId());
            case 21:
                androidx.compose.ui.semantics.v semantics = (androidx.compose.ui.semantics.v) obj;
                Intrinsics.checkNotNullParameter(semantics, "$this$semantics");
                androidx.compose.ui.semantics.t.h(semantics, 1);
                return Unit.a;
            case EventType.WINDOW_STATE /* 22 */:
                com.quizlet.features.infra.folder.tag.screenstates.j it15 = (com.quizlet.features.infra.folder.tag.screenstates.j) obj;
                Intrinsics.checkNotNullParameter(it15, "it");
                return Unit.a;
            case EventType.AUDIO /* 23 */:
                Y popUpTo = (Y) obj;
                Intrinsics.checkNotNullParameter(popUpTo, "$this$popUpTo");
                popUpTo.a = true;
                return Unit.a;
            case EventType.VIDEO /* 24 */:
                Y popUpTo2 = (Y) obj;
                Intrinsics.checkNotNullParameter(popUpTo2, "$this$popUpTo");
                popUpTo2.a = true;
                return Unit.a;
            case EventType.SUBS /* 25 */:
                ((Boolean) obj).booleanValue();
                return Unit.a;
            case EventType.CDN /* 26 */:
                com.quizlet.features.practicetest.common.data.i it16 = (com.quizlet.features.practicetest.common.data.i) obj;
                Intrinsics.checkNotNullParameter(it16, "it");
                return Integer.valueOf(it16.a + 1);
            case 27:
                com.quizlet.features.practicetest.detail.data.p it17 = (com.quizlet.features.practicetest.detail.data.p) obj;
                Intrinsics.checkNotNullParameter(it17, "it");
                return Unit.a;
            case 28:
                Object[] args = {(String) obj};
                Intrinsics.checkNotNullParameter(args, "args");
                return new com.quizlet.qutils.string.f(R.string.share_question_bank_url, C4933y.P(args));
            default:
                return Unit.a;
        }
    }
}

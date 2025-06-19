package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables;

import androidx.compose.ui.text.H;
import com.comscore.streaming.EventType;
import com.quizlet.features.notes.common.events.G;
import com.quizlet.features.practicetest.detail.data.C4403f;
import com.quizlet.features.practicetest.takingtest.data.C4419m;
import com.quizlet.features.universaluploadflow.data.C4462k;
import com.quizlet.features.universaluploadflow.data.L;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.C4761c;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class l implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;

    public /* synthetic */ l(int i, Function1 function1) {
        this.a = i;
        this.b = function1;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                String it2 = (String) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                this.b.invoke(new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.i(it2));
                break;
            case 1:
                List it3 = (List) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                if (!it3.isEmpty()) {
                    this.b.invoke(it3);
                }
                break;
            case 2:
                String it4 = (String) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                this.b.invoke(new com.quizlet.features.notes.common.events.q(it4));
                break;
            case 3:
                this.b.invoke(new com.quizlet.features.notes.common.events.r(((Boolean) obj).booleanValue()));
                break;
            case 4:
                com.quizlet.features.notes.common.events.o it5 = (com.quizlet.features.notes.common.events.o) obj;
                Intrinsics.checkNotNullParameter(it5, "it");
                this.b.invoke(it5);
                break;
            case 5:
                com.quizlet.features.notes.detail.menu.f it6 = (com.quizlet.features.notes.detail.menu.f) obj;
                Intrinsics.checkNotNullParameter(it6, "it");
                this.b.invoke(new com.quizlet.features.notes.common.events.o(it6));
                break;
            case 6:
                this.b.invoke(new G(((Boolean) obj).booleanValue()));
                break;
            case 7:
                List it7 = (List) obj;
                Intrinsics.checkNotNullParameter(it7, "it");
                this.b.invoke(new com.quizlet.features.notes.common.events.E(it7));
                break;
            case 8:
                List it8 = (List) obj;
                Intrinsics.checkNotNullParameter(it8, "it");
                this.b.invoke(new com.quizlet.features.notes.common.events.D(it8));
                break;
            case 9:
                String practiceTestId = (String) obj;
                Intrinsics.checkNotNullParameter(practiceTestId, "practiceTestId");
                this.b.invoke(new C4403f(practiceTestId));
                break;
            case 10:
                com.quizlet.ui.models.webpage.m quizletWebPage = (com.quizlet.ui.models.webpage.m) obj;
                Intrinsics.checkNotNullParameter(quizletWebPage, "quizletWebPage");
                this.b.invoke(new com.quizlet.features.practicetest.detail.data.o(quizletWebPage));
                break;
            case 11:
                Integer num = (Integer) obj;
                num.intValue();
                this.b.invoke(num);
                break;
            case 12:
                this.b.invoke(new C4419m(((Integer) obj).intValue()));
                break;
            case 13:
                com.quizlet.assembly.compose.components.flashcards.b it9 = (com.quizlet.assembly.compose.components.flashcards.b) obj;
                Intrinsics.checkNotNullParameter(it9, "it");
                this.b.invoke(it9);
                break;
            case 14:
                L it10 = (L) obj;
                Intrinsics.checkNotNullParameter(it10, "it");
                this.b.invoke(new com.quizlet.features.universaluploadflow.data.o(it10));
                break;
            case 15:
                com.quizlet.features.universaluploadflow.data.u it11 = (com.quizlet.features.universaluploadflow.data.u) obj;
                Intrinsics.checkNotNullParameter(it11, "it");
                this.b.invoke(new C4462k(it11));
                break;
            case 16:
                com.quizlet.ui.models.webpage.m it12 = (com.quizlet.ui.models.webpage.m) obj;
                Intrinsics.checkNotNullParameter(it12, "it");
                this.b.invoke(new com.quizlet.features.universaluploadflow.data.q(it12));
                break;
            case 17:
                this.b.invoke(new com.quizlet.features.universaluploadflow.flashcards.data.d(((Long) obj).longValue()));
                break;
            case 18:
                this.b.invoke(new com.quizlet.features.universaluploadflow.flashcards.data.g((String) obj));
                break;
            case 19:
                String it13 = (String) obj;
                Intrinsics.checkNotNullParameter(it13, "it");
                this.b.invoke(it13);
                break;
            case 20:
                String it14 = (String) obj;
                Intrinsics.checkNotNullParameter(it14, "it");
                this.b.invoke(new com.quizlet.features.universaluploadflow.pastetext.data.d(it14));
                break;
            case 21:
                String email = (String) obj;
                Intrinsics.checkNotNullParameter(email, "email");
                this.b.invoke(new com.quizlet.login.parentemail.data.c(email));
                break;
            case EventType.WINDOW_STATE /* 22 */:
                String email2 = (String) obj;
                Intrinsics.checkNotNullParameter(email2, "email");
                this.b.invoke(new com.quizlet.login.resetpassword.data.b(email2));
                break;
            case EventType.AUDIO /* 23 */:
                String email3 = (String) obj;
                Intrinsics.checkNotNullParameter(email3, "email");
                this.b.invoke(new com.quizlet.login.signup.data.e(email3));
                break;
            case EventType.VIDEO /* 24 */:
                this.b.invoke(new com.quizlet.login.signup.data.d(((Long) obj).longValue()));
                break;
            case EventType.SUBS /* 25 */:
                String it15 = (String) obj;
                Intrinsics.checkNotNullParameter(it15, "it");
                this.b.invoke(it15);
                break;
            case EventType.CDN /* 26 */:
                Throwable it16 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(it16, "it");
                this.b.invoke(it16);
                break;
            case 27:
                String url = (String) obj;
                Intrinsics.checkNotNullParameter(url, "url");
                this.b.invoke(new C4761c(url));
                break;
            case 28:
                H it17 = (H) obj;
                Intrinsics.checkNotNullParameter(it17, "it");
                this.b.invoke(it17);
                break;
            default:
                H it18 = (H) obj;
                Intrinsics.checkNotNullParameter(it18, "it");
                this.b.invoke(it18);
                break;
        }
        return Unit.a;
    }
}

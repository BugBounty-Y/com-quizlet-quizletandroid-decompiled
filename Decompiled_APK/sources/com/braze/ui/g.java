package com.braze.ui;

import androidx.compose.material.navigation.i;
import androidx.compose.material.navigation.j;
import androidx.compose.ui.n;
import androidx.navigation.E;
import androidx.navigation.compose.v;
import com.google.android.gms.internal.mlkit_vision_camera.N1;
import com.quizlet.eventlogger.features.practicetest.PracticeTestEventLog;
import com.quizlet.quizletandroid.ui.globalnav.composable.u;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem$Create;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem$FreeTrial;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem$Home;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem$Upgrade;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem$YourLibrary;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4739h;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.collections.L;
import kotlin.collections.V;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class g implements Function1 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    public /* synthetic */ g(UserJavascriptInterfaceBase userJavascriptInterfaceBase, String str, String str2, boolean z) {
        this.e = userJavascriptInterfaceBase;
        this.c = str;
        this.d = str2;
        this.b = z;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                break;
            case 1:
                PracticeTestEventLog.Payload createEvent = (PracticeTestEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setAdditionalInfo(new PracticeTestEventLog.AdditionalInfo(null, null, null, null, null, null, null, null, Boolean.valueOf(this.b), 255, null));
                createEvent.setPracticeTestSessionId((String) this.c);
                createEvent.setPracticeTestInstanceId((String) this.d);
                createEvent.setQuestionBankId((String) this.e);
                createEvent.setScreen("results");
                break;
            default:
                E NavHost = (E) obj;
                Intrinsics.checkNotNullParameter(NavHost, "$this$NavHost");
                boolean z = this.b;
                com.quizlet.quizletandroid.ui.globalnav.navigation.a aVar = (com.quizlet.quizletandroid.ui.globalnav.navigation.a) this.e;
                n nVar = (n) this.c;
                androidx.compose.runtime.internal.d dVar = new androidx.compose.runtime.internal.d(true, 1133148745, new u(z, aVar, nVar));
                L lC = V.c();
                K k = K.a;
                N1.h(NavHost, kotlin.jvm.internal.K.a(GlobalNavSuiteItem$Home.class), lC, k, dVar);
                GlobalNavSuiteItem$Create.INSTANCE.getClass();
                j navDestination = new j((i) NavHost.g.b(i.class), new androidx.compose.runtime.internal.d(true, 1988351750, new v((C4739h) this.d, 2)));
                Intrinsics.checkNotNullParameter(navDestination, "navDestination");
                NavHost.j.add(navDestination.a());
                androidx.compose.runtime.internal.d dVar2 = new androidx.compose.runtime.internal.d(true, 1306407616, new com.quizlet.quizletandroid.ui.globalnav.composable.v(nVar, 0));
                N1.h(NavHost, kotlin.jvm.internal.K.a(GlobalNavSuiteItem$YourLibrary.class), V.c(), k, dVar2);
                androidx.compose.runtime.internal.d dVar3 = new androidx.compose.runtime.internal.d(true, -849719807, new com.quizlet.quizletandroid.ui.globalnav.composable.v(nVar, 1));
                N1.h(NavHost, kotlin.jvm.internal.K.a(GlobalNavSuiteItem$FreeTrial.class), V.c(), k, dVar3);
                androidx.compose.runtime.internal.d dVar4 = new androidx.compose.runtime.internal.d(true, 1289120066, new com.quizlet.quizletandroid.ui.globalnav.composable.v(nVar, 2));
                N1.h(NavHost, kotlin.jvm.internal.K.a(GlobalNavSuiteItem$Upgrade.class), V.c(), k, dVar4);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ g(String str, String str2, String str3, boolean z) {
        this.b = z;
        this.c = str;
        this.d = str2;
        this.e = str3;
    }

    public /* synthetic */ g(boolean z, com.quizlet.quizletandroid.ui.globalnav.navigation.a aVar, n nVar, C4739h c4739h) {
        this.b = z;
        this.e = aVar;
        this.c = nVar;
        this.d = c4739h;
    }
}

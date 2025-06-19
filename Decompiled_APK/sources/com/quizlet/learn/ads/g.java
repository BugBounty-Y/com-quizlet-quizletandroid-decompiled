package com.quizlet.learn.ads;

import androidx.lifecycle.p0;
import androidx.navigation.H;
import androidx.navigation.r;
import com.comscore.streaming.EventType;
import com.quizlet.ads.data.AdDataType;
import com.quizlet.eventlogger.model.LearnPostCompletionEventLog;
import com.quizlet.learn.data.C4541f;
import com.quizlet.learn.data.C4542g;
import com.quizlet.learn.viewmodel.C4556c;
import com.quizlet.local.datastore.preferences.C4566c0;
import com.quizlet.quizletandroid.ui.classcreation.i;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.G;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final /* synthetic */ class g extends C4956o implements Function0 {
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ g(int i, Object obj, Class cls, String str, String str2, int i2, int i3) {
        super(i, i2, cls, obj, str, str2);
        this.a = i3;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                h hVar = (h) this.receiver;
                AdDataType adDataType = hVar.d;
                if (adDataType != null) {
                    hVar.d = null;
                    hVar.f.b(adDataType);
                }
                break;
            case 1:
                C4556c c4556c = (C4556c) this.receiver;
                String progressState = c4556c.g.a;
                com.quizlet.learn.logging.d dVar = c4556c.d;
                dVar.getClass();
                Intrinsics.checkNotNullParameter("practice_more", "buttonName");
                Intrinsics.checkNotNullParameter(progressState, "progressState");
                LearnPostCompletionEventLog.Companion companion = LearnPostCompletionEventLog.b;
                com.braze.ui.e eVar = new com.braze.ui.e(8, "practice_more", progressState);
                companion.getClass();
                dVar.a.l(LearnPostCompletionEventLog.Companion.a("learn_ending_button_clicked", eVar));
                c4556c.i.j(C4542g.a);
                break;
            case 2:
                C4556c c4556c2 = (C4556c) this.receiver;
                String progressState2 = c4556c2.g.a;
                com.quizlet.learn.logging.d dVar2 = c4556c2.d;
                dVar2.getClass();
                Intrinsics.checkNotNullParameter("take_test", "buttonName");
                Intrinsics.checkNotNullParameter(progressState2, "progressState");
                LearnPostCompletionEventLog.Companion companion2 = LearnPostCompletionEventLog.b;
                com.braze.ui.e eVar2 = new com.braze.ui.e(8, "take_test", progressState2);
                companion2.getClass();
                dVar2.a.l(LearnPostCompletionEventLog.Companion.a("learn_ending_button_clicked", eVar2));
                c4556c2.i.j(C4541f.a);
                break;
            case 3:
                C4556c c4556c3 = (C4556c) this.receiver;
                String progressState3 = c4556c3.g.a;
                com.quizlet.learn.logging.d dVar3 = c4556c3.d;
                dVar3.getClass();
                Intrinsics.checkNotNullParameter("take_test", "buttonName");
                Intrinsics.checkNotNullParameter(progressState3, "progressState");
                LearnPostCompletionEventLog.Companion companion3 = LearnPostCompletionEventLog.b;
                com.braze.ui.e eVar3 = new com.braze.ui.e(8, "take_test", progressState3);
                companion3.getClass();
                dVar3.a.l(LearnPostCompletionEventLog.Companion.a("learn_ending_button_clicked", eVar3));
                c4556c3.i.j(C4541f.a);
                break;
            case 4:
                C4556c c4556c4 = (C4556c) this.receiver;
                String progressState4 = c4556c4.g.a;
                com.quizlet.learn.logging.d dVar4 = c4556c4.d;
                dVar4.getClass();
                Intrinsics.checkNotNullParameter("practice_more", "buttonName");
                Intrinsics.checkNotNullParameter(progressState4, "progressState");
                LearnPostCompletionEventLog.Companion companion4 = LearnPostCompletionEventLog.b;
                com.braze.ui.e eVar4 = new com.braze.ui.e(8, "practice_more", progressState4);
                companion4.getClass();
                dVar4.a.l(LearnPostCompletionEventLog.Companion.a("learn_ending_button_clicked", eVar4));
                c4556c4.i.j(C4542g.a);
                break;
            case 5:
                H h = (H) this.receiver;
                Intrinsics.checkNotNullParameter(h, "<this>");
                h.c("login", new C4566c0(15));
                break;
            case 6:
                H h2 = (H) this.receiver;
                Intrinsics.checkNotNullParameter(h2, "<this>");
                h2.c("signup", new C4566c0(14));
                break;
            case 7:
                ((com.quizlet.quizletandroid.ui.navigationmanagers.d) this.receiver).b();
                break;
            case 8:
                ((com.quizlet.quizletandroid.ui.navigationmanagers.d) this.receiver).e();
                break;
            case 9:
                H h3 = (H) this.receiver;
                Intrinsics.checkNotNullParameter(h3, "<this>");
                r.d(h3, "invalid_magic_link");
                break;
            case 10:
                com.quizlet.quizletandroid.ui.debug.a aVar = ((com.quizlet.quizletandroid.ui.navigationmanagers.d) this.receiver).c;
                break;
            case 11:
                ((com.quizlet.quizletandroid.ui.navigationmanagers.d) this.receiver).b();
                break;
            case 12:
                ((com.quizlet.quizletandroid.ui.navigationmanagers.d) this.receiver).e();
                break;
            case 13:
                H h4 = (H) this.receiver;
                Intrinsics.checkNotNullParameter(h4, "<this>");
                h4.c("reset_password", new C4566c0(17));
                break;
            case 14:
                ((com.quizlet.quizletandroid.ui.navigationmanagers.d) this.receiver).c();
                break;
            case 15:
                ((com.quizlet.quizletandroid.ui.navigationmanagers.d) this.receiver).a();
                break;
            case 16:
                ((com.quizlet.quizletandroid.ui.navigationmanagers.d) this.receiver).b();
                break;
            case 17:
                ((com.quizlet.quizletandroid.ui.navigationmanagers.d) this.receiver).e();
                break;
            case 18:
                ((com.quizlet.quizletandroid.ui.navigationmanagers.d) this.receiver).a();
                break;
            case 19:
                ((com.quizlet.quizletandroid.ui.navigationmanagers.d) this.receiver).c();
                break;
            case 20:
                ((com.quizlet.quizletandroid.ui.navigationmanagers.d) this.receiver).a();
                break;
            case 21:
                ((com.quizlet.quizletandroid.ui.navigationmanagers.d) this.receiver).b();
                break;
            case EventType.WINDOW_STATE /* 22 */:
                ((com.quizlet.quizletandroid.ui.navigationmanagers.d) this.receiver).e();
                break;
            case EventType.AUDIO /* 23 */:
                ((com.quizlet.quizletandroid.ui.navigationmanagers.d) this.receiver).c();
                break;
            case EventType.VIDEO /* 24 */:
                ((com.quizlet.login.magiclink.viewmodel.g) this.receiver).A();
                break;
            case EventType.SUBS /* 25 */:
                ((com.quizlet.login.magiclink.viewmodel.g) ((com.quizlet.login.magiclink.viewmodel.a) this.receiver)).A();
                break;
            case EventType.CDN /* 26 */:
                ((com.quizlet.login.magiclink.viewmodel.g) ((com.quizlet.login.magiclink.viewmodel.a) this.receiver)).c.a(false);
                break;
            case 27:
                i iVar = (i) this.receiver;
                iVar.getClass();
                E.A(p0.j(iVar), null, null, new com.quizlet.quizletandroid.ui.classcreation.g(iVar, null), 3);
                break;
            case 28:
                i iVar2 = (i) this.receiver;
                iVar2.getClass();
                E.A(p0.j(iVar2), null, null, new com.quizlet.quizletandroid.ui.classcreation.f(iVar2, null), 3);
                break;
            default:
                L l = (L) this.receiver;
                l.getClass();
                E.A(p0.j(l), null, null, new G(l, null), 3);
                break;
        }
        return Unit.a;
    }
}

package com.quizlet.features.flashcards.navigation;

import androidx.lifecycle.p0;
import androidx.navigation.H;
import com.comscore.streaming.EventType;
import com.quizlet.assembly.compose.modals.x;
import com.quizlet.data.model.EnumC4167t0;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4738g;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4739h;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.C4942a;
import kotlinx.coroutines.E;

/* loaded from: classes2.dex */
public final /* synthetic */ class c extends C4942a implements Function0 {
    public final /* synthetic */ int h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ c(int i, Object obj, Class cls, String str, String str2, int i2, int i3) {
        super(i, i2, cls, obj, str, str2);
        this.h = i3;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.h) {
            case 0:
                ((H) this.a).e();
                break;
            case 1:
                ((H) this.a).e();
                break;
            case 2:
                ((H) this.a).e();
                break;
            case 3:
                x.d((x) this.a);
                break;
            case 4:
                x.d((x) this.a);
                break;
            case 5:
                x.d((x) this.a);
                break;
            case 6:
                ((H) this.a).e();
                break;
            case 7:
                ((H) this.a).e();
                break;
            case 8:
                ((H) this.a).e();
                break;
            case 9:
                ((com.quizlet.features.infra.logout.viewmodels.a) this.a).v(EnumC4167t0.a);
                break;
            case 10:
                ((H) this.a).e();
                break;
            case 11:
                ((H) this.a).e();
                break;
            case 12:
                ((H) this.a).e();
                break;
            case 13:
                ((H) this.a).e();
                break;
            case 14:
                ((H) this.a).e();
                break;
            case 15:
                ((H) this.a).e();
                break;
            case 16:
                ((H) this.a).e();
                break;
            case 17:
                ((H) this.a).e();
                break;
            case 18:
                ((H) this.a).e();
                break;
            case 19:
                ((H) this.a).e();
                break;
            case 20:
                ((H) this.a).e();
                break;
            case 21:
                ((H) this.a).e();
                break;
            case EventType.WINDOW_STATE /* 22 */:
                ((H) this.a).e();
                break;
            case EventType.AUDIO /* 23 */:
                ((H) this.a).e();
                break;
            case EventType.VIDEO /* 24 */:
                ((H) this.a).e();
                break;
            case EventType.SUBS /* 25 */:
                ((H) this.a).e();
                break;
            case EventType.CDN /* 26 */:
                ((H) this.a).e();
                break;
            case 27:
                ((H) this.a).f();
                break;
            case 28:
                ((com.quizlet.quizletandroid.ui.globalnav.navigation.a) this.a).b(null);
                break;
            default:
                C4739h c4739h = (C4739h) this.a;
                com.quizlet.quizletandroid.ui.startpage.nav2.logging.c cVar = c4739h.e;
                cVar.getClass();
                com.quizlet.quizletandroid.ui.startpage.nav2.logging.c.a(cVar, "clicked_create_magic_notes");
                E.A(p0.j(c4739h), null, null, new C4738g(c4739h, null), 3);
                break;
        }
        return Unit.a;
    }
}

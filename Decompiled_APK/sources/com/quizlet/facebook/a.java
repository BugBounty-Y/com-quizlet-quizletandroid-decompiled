package com.quizlet.facebook;

import com.comscore.streaming.EventType;
import com.facebook.login.B;
import com.quizlet.features.achievements.data.c;
import com.quizlet.features.folders.addtofolder.data.d;
import com.quizlet.features.folders.addtofolder.data.g;
import com.quizlet.features.folders.addtofolder.data.h;
import com.quizlet.features.folders.addtofolder.data.i;
import com.quizlet.features.folders.addtofolder.data.j;
import com.quizlet.features.folders.data.A;
import com.quizlet.features.folders.data.C4274c;
import com.quizlet.features.folders.data.C4276d;
import com.quizlet.features.folders.data.C4278e;
import com.quizlet.features.folders.data.C4300p;
import com.quizlet.features.folders.data.C4305s;
import com.quizlet.features.folders.data.D;
import com.quizlet.features.folders.data.E;
import com.quizlet.features.folders.data.F;
import com.quizlet.features.folders.data.G;
import com.quizlet.features.folders.data.r;
import com.quizlet.features.home.data.e;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;

    public /* synthetic */ a(int i, Function1 function1) {
        this.a = i;
        this.b = function1;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.invoke(B.b.a());
                break;
            case 1:
                this.b.invoke(c.a);
                break;
            case 2:
                this.b.invoke(com.quizlet.features.achievements.data.b.a);
                break;
            case 3:
                this.b.invoke(Boolean.TRUE);
                break;
            case 4:
                this.b.invoke(com.quizlet.features.folders.addtofolder.data.c.a);
                break;
            case 5:
                this.b.invoke(d.a);
                break;
            case 6:
                this.b.invoke(g.a);
                break;
            case 7:
                this.b.invoke(h.a);
                break;
            case 8:
                this.b.invoke(j.a);
                break;
            case 9:
                this.b.invoke(i.a);
                break;
            case 10:
                this.b.invoke(com.quizlet.features.folders.changetags.data.c.a);
                break;
            case 11:
                this.b.invoke(com.quizlet.features.folders.changetags.data.c.a);
                break;
            case 12:
                this.b.invoke(D.a);
                break;
            case 13:
                this.b.invoke(C4274c.a);
                break;
            case 14:
                this.b.invoke(E.a);
                break;
            case 15:
                this.b.invoke(F.a);
                break;
            case 16:
                this.b.invoke(A.a);
                break;
            case 17:
                this.b.invoke(new C4276d("folder_page_top_add"));
                break;
            case 18:
                this.b.invoke(r.a);
                break;
            case 19:
                this.b.invoke(C4305s.a);
                break;
            case 20:
                this.b.invoke(C4278e.a);
                break;
            case 21:
                this.b.invoke(G.a);
                break;
            case EventType.WINDOW_STATE /* 22 */:
                this.b.invoke(C4300p.a);
                break;
            case EventType.AUDIO /* 23 */:
                this.b.invoke(new C4276d("folder_page_empty_folder"));
                break;
            case EventType.VIDEO /* 24 */:
                this.b.invoke(com.quizlet.features.home.data.c.a);
                break;
            case EventType.SUBS /* 25 */:
                this.b.invoke(e.a);
                break;
            case EventType.CDN /* 26 */:
                this.b.invoke(com.quizlet.features.home.data.a.a);
                break;
            case 27:
                this.b.invoke(com.quizlet.features.infra.folder.create.coursefolder.data.h.a);
                break;
            case 28:
                this.b.invoke(com.quizlet.features.infra.folder.create.coursefolder.data.h.a);
                break;
            default:
                this.b.invoke(com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.h.a);
                break;
        }
        return Unit.a;
    }
}

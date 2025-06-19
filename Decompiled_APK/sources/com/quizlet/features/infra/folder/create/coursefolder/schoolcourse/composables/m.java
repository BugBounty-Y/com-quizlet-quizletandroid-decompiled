package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables;

import com.comscore.streaming.EventType;
import com.quizlet.data.model.EnumC4167t0;
import com.quizlet.features.notes.common.events.C4374e;
import com.quizlet.features.notes.common.events.C4375f;
import com.quizlet.features.notes.common.events.C4376g;
import com.quizlet.features.notes.common.events.C4377h;
import com.quizlet.features.notes.common.events.C4378i;
import com.quizlet.features.notes.common.events.C4379j;
import com.quizlet.features.notes.common.events.C4380k;
import com.quizlet.features.notes.common.events.C4381l;
import com.quizlet.features.notes.common.events.H;
import com.quizlet.features.notes.common.events.L;
import com.quizlet.features.practicetest.detail.data.C4401d;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final /* synthetic */ class m implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;

    public /* synthetic */ m(int i, Function1 function1) {
        this.a = i;
        this.b = function1;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.invoke(com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.g.a);
                break;
            case 1:
                this.b.invoke(com.quizlet.features.infra.folder.tag.screenstates.f.a);
                break;
            case 2:
                this.b.invoke(EnumC4167t0.b);
                break;
            case 3:
                this.b.invoke(EnumC4167t0.c);
                break;
            case 4:
                this.b.invoke(C4374e.a);
                break;
            case 5:
                this.b.invoke(com.quizlet.features.notes.common.events.p.a);
                break;
            case 6:
                this.b.invoke(C4377h.a);
                break;
            case 7:
                this.b.invoke(C4379j.a);
                break;
            case 8:
                this.b.invoke(C4376g.a);
                break;
            case 9:
                this.b.invoke(C4380k.a);
                break;
            case 10:
                this.b.invoke(C4378i.a);
                break;
            case 11:
                this.b.invoke(C4381l.a);
                break;
            case 12:
                this.b.invoke(com.quizlet.features.notes.common.events.m.a);
                break;
            case 13:
                this.b.invoke(com.quizlet.features.notes.common.events.w.a);
                break;
            case 14:
                this.b.invoke(com.quizlet.features.notes.common.events.v.a);
                break;
            case 15:
                this.b.invoke(C4375f.a);
                break;
            case 16:
                this.b.invoke(com.quizlet.features.notes.common.events.n.a);
                break;
            case 17:
                this.b.invoke(com.quizlet.features.notes.common.events.B.a);
                break;
            case 18:
                this.b.invoke(L.a);
                break;
            case 19:
                this.b.invoke(com.quizlet.features.notes.common.events.C.a);
                break;
            case 20:
                this.b.invoke(H.a);
                break;
            case 21:
                this.b.invoke(com.quizlet.features.onboarding.ell.f.a);
                break;
            case EventType.WINDOW_STATE /* 22 */:
                this.b.invoke(com.quizlet.features.onboarding.ell.g.a);
                break;
            case EventType.AUDIO /* 23 */:
                this.b.invoke(com.quizlet.features.onboarding.ell.j.a);
                break;
            case EventType.VIDEO /* 24 */:
                this.b.invoke(com.quizlet.features.onboarding.ell.k.a);
                break;
            case EventType.SUBS /* 25 */:
                this.b.invoke(Boolean.TRUE);
                break;
            case EventType.CDN /* 26 */:
                this.b.invoke(Boolean.FALSE);
                break;
            case 27:
                this.b.invoke(com.quizlet.features.practicetest.detail.data.n.a);
                break;
            case 28:
                this.b.invoke(com.quizlet.features.practicetest.detail.data.k.a);
                break;
            default:
                this.b.invoke(C4401d.a);
                break;
        }
        return Unit.a;
    }
}

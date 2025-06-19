package com.quizlet.features.flashcards;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.Y;
import com.quizlet.studiablemodels.StudiableAudio;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes2.dex */
public final class E extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ S k;
    public final /* synthetic */ StudiableAudio l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public E(S s, StudiableAudio studiableAudio, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = s;
        this.l = studiableAudio;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new E(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((E) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        com.quizlet.features.flashcards.data.b bVar;
        s0 s0Var;
        Object value;
        com.quizlet.features.flashcards.engine.h hVar;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        S s = this.k;
        if (i == 0) {
            Z.e(obj);
            boolean z = s.G().g;
            Y y = s.t;
            if (z) {
                s.d.b(true);
                y.l(com.quizlet.features.flashcards.data.o.a(s.G(), 0, 0, 0, 0, false, false, false, false, null, null, 959));
                return Unit.a;
            }
            com.quizlet.features.flashcards.logging.a.a(s.c.d, "audio_button_tapped", null, null, null, 62);
            y.l(com.quizlet.features.flashcards.data.o.a(s.G(), 0, 0, 0, 0, false, false, true, false, null, null, 959));
            String str = this.l.a;
            this.j = 1;
            if (S.B(s, str, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        s.t.l(com.quizlet.features.flashcards.data.o.a(s.G(), 0, 0, 0, 0, false, false, false, false, null, null, 959));
        if (s.G().f && (bVar = s.G().j) != null) {
            do {
                s0Var = s.u;
                value = s0Var.getValue();
                hVar = s.c;
            } while (!s0Var.k(value, new com.quizlet.features.flashcards.autoplay.q(bVar, hVar.d().c, hVar)));
        }
        return Unit.a;
    }
}

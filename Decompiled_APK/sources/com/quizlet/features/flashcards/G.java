package com.quizlet.features.flashcards;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.p0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.y0;

/* loaded from: classes2.dex */
public final class G extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ S k;
    public final /* synthetic */ com.quizlet.features.flashcards.settings.d l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public G(S s, com.quizlet.features.flashcards.settings.d dVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = s;
        this.l = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new G(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((G) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.features.flashcards.settings.d dVar = this.l;
            S s = this.k;
            s.c.q(dVar.a);
            s.H();
            if (dVar.c) {
                y0 y0Var = s.D;
                if (y0Var != null) {
                    y0Var.j(null);
                }
                s.D = kotlinx.coroutines.E.A(p0.j(s), com.facebook.appevents.iap.u.d(), null, new J(s, null), 2);
            } else if (dVar.b) {
                this.j = 1;
                if (s.c.i(this) == aVar) {
                    return aVar;
                }
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}

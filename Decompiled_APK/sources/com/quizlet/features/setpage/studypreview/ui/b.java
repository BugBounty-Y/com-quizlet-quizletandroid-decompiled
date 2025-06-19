package com.quizlet.features.setpage.studypreview.ui;

import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.animation.core.C0238e;
import androidx.compose.animation.core.K0;
import androidx.compose.runtime.snapshots.q;
import androidx.glance.appwidget.protobuf.Z;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class b extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C0238e k;
    public final /* synthetic */ q l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(C0238e c0238e, q qVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c0238e;
        this.l = qVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new b(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        b bVar;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            Float f = new Float(DefinitionKt.NO_Float_VALUE);
            K0 k0R = AbstractC0240f.r(700, 0, null, 6);
            this.j = 1;
            bVar = this;
            if (C0238e.c(this.k, f, k0R, null, bVar, 12) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            bVar = this;
        }
        q qVar = bVar.l;
        qVar.set(0, ((com.quizlet.assembly.compose.components.flashcards.b) qVar.get(0)).a());
        return Unit.a;
    }
}

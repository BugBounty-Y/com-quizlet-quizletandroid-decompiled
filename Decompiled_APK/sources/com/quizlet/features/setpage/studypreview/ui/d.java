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
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C0238e l;
    public final /* synthetic */ C0238e m;
    public final /* synthetic */ q n;
    public final /* synthetic */ C0238e o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(C0238e c0238e, C0238e c0238e2, q qVar, C0238e c0238e3, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = c0238e;
        this.m = c0238e2;
        this.n = qVar;
        this.o = c0238e3;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        d dVar = new d(this.l, this.m, this.n, this.o, hVar);
        dVar.k = obj;
        return dVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        d dVar;
        C c;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            C c2 = (C) this.k;
            Float f = new Float(DefinitionKt.NO_Float_VALUE);
            K0 k0R = AbstractC0240f.r(700, 0, null, 6);
            this.k = c2;
            this.j = 1;
            dVar = this;
            if (C0238e.c(this.l, f, k0R, null, dVar, 12) == aVar) {
                return aVar;
            }
            c = c2;
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            c = (C) this.k;
            Z.e(obj);
            dVar = this;
        }
        E.A(c, null, null, new b(dVar.m, dVar.n, null), 3);
        E.A(c, null, null, new c(dVar.o, null), 3);
        return Unit.a;
    }
}

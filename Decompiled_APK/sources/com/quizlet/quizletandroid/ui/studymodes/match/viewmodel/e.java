package com.quizlet.quizletandroid.ui.studymodes.match.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.Y;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class e extends i implements Function2 {
    public Y j;
    public int k;
    public final /* synthetic */ g l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(g gVar, h hVar) {
        super(2, hVar);
        this.l = gVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new e(this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Y y;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.k;
        if (i == 0) {
            Z.e(obj);
            g gVar = this.l;
            Y y2 = gVar.w;
            com.quizlet.data.repository.user.a aVar2 = gVar.g;
            this.j = y2;
            this.k = 1;
            obj = aVar2.j(this);
            if (obj == aVar) {
                return aVar;
            }
            y = y2;
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            y = this.j;
            Z.e(obj);
        }
        y.j(obj);
        return Unit.a;
    }
}

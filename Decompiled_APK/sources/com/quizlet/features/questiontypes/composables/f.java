package com.quizlet.features.questiontypes.composables;

import androidx.compose.foundation.text.input.internal.C0496b;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.KotlinNothingValueException;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.Y;

/* loaded from: classes3.dex */
public final class f extends i implements Function2 {
    public int j;
    public final /* synthetic */ Y k;
    public final /* synthetic */ com.quizlet.features.questiontypes.basequestion.i l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(Y y, com.quizlet.features.questiontypes.basequestion.i iVar, h hVar) {
        super(2, hVar);
        this.k = y;
        this.l = iVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new f(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((f) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
        return kotlin.coroutines.intrinsics.a.a;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            C0496b c0496b = new C0496b(this.l, 14);
            this.j = 1;
            if (this.k.a.b(c0496b, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        throw new KotlinNothingValueException();
    }
}

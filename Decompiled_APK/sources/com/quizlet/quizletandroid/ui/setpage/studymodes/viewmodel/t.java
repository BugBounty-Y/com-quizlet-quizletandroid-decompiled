package com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.generated.enums.P;
import com.quizlet.generated.enums.S;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class t extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ y k;
    public final /* synthetic */ long l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public t(y yVar, long j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = yVar;
        this.l = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new t(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((t) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        long j = this.l;
        y yVar = this.k;
        if (i == 0) {
            Z.e(obj);
            P p = P.LEARN_CHECKPOINT;
            this.j = 1;
            obj = y.a(yVar, j, p, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        InterfaceC4176w0 interfaceC4176w0 = (InterfaceC4176w0) obj;
        yVar.getClass();
        if (interfaceC4176w0.B() == S.EXPERIMENT_VARIANT_SET_IN_TEACHER_CLASS) {
            yVar.d.a(j);
        }
        return interfaceC4176w0;
    }
}

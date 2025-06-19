package com.quizlet.explanations.questiondetail.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.quizlet.data.model.Question;
import io.reactivex.rxjava3.internal.operators.single.g;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes2.dex */
public final class e extends i implements Function2 {
    public int j;
    public final /* synthetic */ f k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(f fVar, h hVar) {
        super(2, hVar);
        this.k = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new e(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object value;
        String studyMaterialId;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        f fVar = this.k;
        if (i == 0) {
            Z.e(obj);
            g gVarR = fVar.i.r();
            this.j = 1;
            obj = I1.b(gVarR, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        boolean z = !((Boolean) obj).booleanValue();
        s0 s0Var = fVar.z;
        do {
            value = s0Var.getValue();
            com.quizlet.explanations.questiondetail.data.a aVar2 = (com.quizlet.explanations.questiondetail.data.a) value;
            Question question = fVar.A;
            if (question == null || (studyMaterialId = question.d) == null) {
                studyMaterialId = "";
            }
            aVar2.getClass();
            Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        } while (!s0Var.k(value, new com.quizlet.explanations.questiondetail.data.a(z, studyMaterialId)));
        return Unit.a;
    }
}

package com.quizlet.explanations.textbook.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.quizlet.explanations.textbook.data.u;
import com.quizlet.generated.enums.y1;
import io.reactivex.rxjava3.internal.operators.single.g;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ c k;
    public final /* synthetic */ boolean l;
    public final /* synthetic */ String m;
    public final /* synthetic */ y1 n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(c cVar, boolean z, String str, y1 y1Var, h hVar) {
        super(2, hVar);
        this.k = cVar;
        this.l = z;
        this.m = str;
        this.n = y1Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.k, this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        c cVar = this.k;
        if (i == 0) {
            Z.e(obj);
            g gVarR = cVar.f.r();
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
        cVar.i.j(new u(this.l, !((Boolean) obj).booleanValue(), this.m, this.n));
        return Unit.a;
    }
}

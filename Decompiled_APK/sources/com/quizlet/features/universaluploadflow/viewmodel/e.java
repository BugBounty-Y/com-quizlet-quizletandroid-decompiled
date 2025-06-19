package com.quizlet.features.universaluploadflow.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.q2;
import com.quizlet.features.universaluploadflow.data.B;
import com.quizlet.generated.enums.EnumC4483g0;
import java.util.ArrayList;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class e extends i implements Function2 {
    public int j;
    public final /* synthetic */ ArrayList k;
    public final /* synthetic */ g l;
    public final /* synthetic */ ArrayList m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(ArrayList arrayList, g gVar, ArrayList arrayList2, h hVar) {
        super(2, hVar);
        this.k = arrayList;
        this.l = gVar;
        this.m = arrayList2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new e(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        g gVar = this.l;
        if (i == 0) {
            Z.e(obj);
            q2 q2Var = new q2(this.k, !gVar.C());
            this.j = 1;
            obj = gVar.c.q(gVar.i, q2Var, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        String str = (String) obj;
        com.quizlet.features.universaluploadflow.logging.b.e(gVar.e, str, gVar.C(), null, this.m, EnumC4483g0.FILE.a(), 4);
        gVar.k.h(new B(str));
        return Unit.a;
    }
}

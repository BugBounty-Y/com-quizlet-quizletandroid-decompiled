package com.quizlet.features.folders.changetags.viewmodel;

import androidx.compose.material.ripple.r;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.C4169u;
import com.quizlet.features.folders.changetags.data.f;
import com.quizlet.generated.enums.y1;
import java.util.ArrayList;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.p;
import kotlin.q;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ d k;
    public final /* synthetic */ String l;
    public final /* synthetic */ y1 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(d dVar, String str, y1 y1Var, h hVar) {
        super(2, hVar);
        this.k = dVar;
        this.l = str;
        this.m = y1Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object objG;
        s0 s0Var;
        Object value;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        d dVar = this.k;
        if (i == 0) {
            Z.e(obj);
            r rVar = dVar.b;
            this.j = 1;
            String str = this.l;
            objG = rVar.g(dVar.d, this.m, str, this);
            if (objG == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            objG = ((kotlin.r) obj).a;
        }
        p pVar = kotlin.r.b;
        if (!(objG instanceof q)) {
            C4169u c4169u = (C4169u) objG;
            Iterable<C4169u> iterable = c4169u.d;
            if (iterable == null) {
                iterable = K.a;
            }
            dVar.getClass();
            ArrayList arrayList = new ArrayList(kotlin.collections.C.q(iterable, 10));
            for (C4169u c4169u2 : iterable) {
                arrayList.add(new com.quizlet.features.infra.folder.menu.data.e(c4169u.a, c4169u2.a, c4169u2.b, c4169u2.c));
            }
            com.quizlet.features.infra.folder.menu.data.b bVar = new com.quizlet.features.infra.folder.menu.data.b(c4169u.a, c4169u.b, false, arrayList);
            kotlinx.collections.immutable.c cVarB = d.B(arrayList);
            do {
                s0Var = dVar.h;
                value = s0Var.getValue();
            } while (!s0Var.k(value, f.a((f) value, false, cVarB, bVar, false, 8)));
        }
        kotlin.r.a(objG);
        return Unit.a;
    }
}

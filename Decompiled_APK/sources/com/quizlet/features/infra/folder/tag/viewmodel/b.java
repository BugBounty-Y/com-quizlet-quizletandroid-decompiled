package com.quizlet.features.infra.folder.tag.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.quizlet.features.infra.folder.tag.screenstates.k;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.p;
import kotlin.q;
import kotlin.r;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ d k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(d dVar, h hVar) {
        super(2, hVar);
        this.k = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object objO;
        Object value;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        d dVar = this.k;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.data.interactor.school.b bVar = dVar.c;
            long j = dVar.f;
            this.j = 1;
            objO = bVar.o(j, this);
            if (objO == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            objO = ((r) obj).a;
        }
        p pVar = r.b;
        if (!(objO instanceof q)) {
            List list = (List) objO;
            s0 s0Var = dVar.i;
            do {
                value = s0Var.getValue();
            } while (!s0Var.k(value, k.a((k) value, null, null, false, AbstractC3409x1.i(CollectionsKt.b0(list, dVar.h)), 7)));
        }
        return Unit.a;
    }
}

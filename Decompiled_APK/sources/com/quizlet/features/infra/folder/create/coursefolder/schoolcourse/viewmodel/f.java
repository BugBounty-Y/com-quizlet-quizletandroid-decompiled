package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.p;
import kotlin.q;
import kotlin.r;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class f extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ o k;
    public final /* synthetic */ com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.f l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(o oVar, com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.f fVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = oVar;
        this.l = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new f(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object obj2;
        Object obj3 = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        o oVar = this.k;
        com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.f fVar = this.l;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.data.repository.widget.b bVar = oVar.f;
            long j = fVar.a;
            this.j = 1;
            Object objH = bVar.h(j, this);
            obj2 = objH;
            if (objH == obj3) {
                return obj3;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            obj2 = ((r) obj).a;
        }
        p pVar = r.b;
        if (!(obj2 instanceof q)) {
            List list = (List) obj2;
            oVar.E(list, com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a.b, fVar.b, true ^ list.isEmpty());
        }
        if (r.a(obj2) != null) {
            o.F(oVar, null, com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a.e, 13);
        }
        return Unit.a;
    }
}

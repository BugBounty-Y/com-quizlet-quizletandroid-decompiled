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
public final class h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ o k;
    public final /* synthetic */ boolean l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(o oVar, boolean z, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = oVar;
        this.l = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new h(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((h) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object objJ;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.data.repository.widget.b bVar = this.k.f;
            this.j = 1;
            objJ = bVar.j(this);
            if (objJ == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            objJ = ((r) obj).a;
        }
        p pVar = r.b;
        if (!(objJ instanceof q)) {
            o.G(this.k, (List) objJ, com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a.b, this.l, !r4.isEmpty(), 4);
        }
        if (r.a(objJ) != null) {
            o.G(this.k, null, com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a.e, false, false, 29);
        }
        return Unit.a;
    }
}

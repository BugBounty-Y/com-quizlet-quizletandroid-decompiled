package com.quizlet.features.infra.folder.create.composables;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.assembly.compose.modals.x;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class o extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ x j;
    public final /* synthetic */ com.quizlet.features.infra.folder.create.coursefolder.viewmodel.f k;
    public final /* synthetic */ String l;
    public final /* synthetic */ com.quizlet.features.infra.folder.create.data.b m;
    public final /* synthetic */ com.quizlet.features.infra.folder.create.data.i n;
    public final /* synthetic */ Long o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public o(x xVar, com.quizlet.features.infra.folder.create.coursefolder.viewmodel.f fVar, String str, com.quizlet.features.infra.folder.create.data.b bVar, com.quizlet.features.infra.folder.create.data.i iVar, Long l, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = xVar;
        this.k = fVar;
        this.l = str;
        this.m = bVar;
        this.n = iVar;
        this.o = l;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new o(this.j, this.k, this.l, this.m, this.n, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((o) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        if (this.j.b()) {
            ((com.quizlet.features.infra.folder.create.coursefolder.viewmodel.e) this.k).B(new com.quizlet.features.infra.folder.create.coursefolder.data.g(this.l, this.m, this.n, this.o));
        }
        return Unit.a;
    }
}

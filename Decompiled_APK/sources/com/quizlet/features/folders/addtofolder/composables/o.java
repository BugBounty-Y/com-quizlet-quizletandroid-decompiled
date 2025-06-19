package com.quizlet.features.folders.addtofolder.composables;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.assembly.compose.modals.x;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class o extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ com.quizlet.features.folders.addtofolder.viewmodel.n j;
    public final /* synthetic */ kotlinx.collections.immutable.b k;
    public final /* synthetic */ long l;
    public final /* synthetic */ long m;
    public final /* synthetic */ String n;
    public final /* synthetic */ x o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public o(com.quizlet.features.folders.addtofolder.viewmodel.n nVar, kotlinx.collections.immutable.b bVar, long j, long j2, String str, x xVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = nVar;
        this.k = bVar;
        this.l = j;
        this.m = j2;
        this.n = str;
        this.o = xVar;
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
        boolean zB = this.o.b();
        ((com.quizlet.features.folders.addtofolder.viewmodel.m) this.j).I(new com.quizlet.features.folders.addtofolder.data.e(this.k, this.l, this.m, this.n, zB));
        return Unit.a;
    }
}

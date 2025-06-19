package com.quizlet.features.infra.folder.save.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.generated.enums.y1;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes3.dex */
public final class a extends i implements Function2 {
    public final /* synthetic */ c j;
    public final /* synthetic */ y1 k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(c cVar, y1 y1Var, String str, h hVar) {
        super(2, hVar);
        this.j = cVar;
        this.k = y1Var;
        this.l = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new a(this.j, this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((InterfaceC5002j) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        c cVar = this.j;
        cVar.d = this.k;
        cVar.e = this.l;
        cVar.A();
        return Unit.a;
    }
}

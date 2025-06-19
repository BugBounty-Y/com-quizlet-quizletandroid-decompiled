package com.braze.communication.dust;

import androidx.glance.appwidget.protobuf.Z;
import java.io.BufferedReader;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.E;
import kotlinx.coroutines.O;
import kotlinx.coroutines.channels.u;

/* loaded from: classes.dex */
public final class d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int a;
    public /* synthetic */ Object b;
    public final /* synthetic */ BufferedReader c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(BufferedReader bufferedReader, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.c = bufferedReader;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        d dVar = new d(this.c, hVar);
        dVar.b = obj;
        return dVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        d dVar = new d(this.c, (kotlin.coroutines.h) obj2);
        dVar.b = (u) obj;
        return dVar.invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        u uVar;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.a;
        if (i == 0) {
            Z.e(obj);
            uVar = (u) this.b;
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            uVar = (u) this.b;
            Z.e(obj);
        }
        while (E.x(uVar)) {
            kotlinx.coroutines.scheduling.e eVar = O.a;
            kotlinx.coroutines.scheduling.d dVar = kotlinx.coroutines.scheduling.d.b;
            c cVar = new c(this.c, uVar, null);
            this.b = uVar;
            this.a = 1;
            if (E.J(dVar, cVar, this) == aVar) {
                return aVar;
            }
        }
        return Unit.a;
    }
}

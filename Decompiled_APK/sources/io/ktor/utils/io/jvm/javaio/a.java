package io.ktor.utils.io.jvm.javaio;

import androidx.glance.appwidget.protobuf.Z;
import io.ktor.utils.io.n;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class a extends i implements Function2 {
    public int j;
    public final /* synthetic */ n k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(n nVar, h hVar) {
        super(2, hVar);
        this.k = nVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new a(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            return obj;
        }
        Z.e(obj);
        this.j = 1;
        Object objE = this.k.e(1, this);
        return objE == aVar ? aVar : objE;
    }
}

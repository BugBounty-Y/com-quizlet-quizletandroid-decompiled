package androidx.compose.material3;

import androidx.compose.material3.internal.AbstractC0646j;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.w2, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0751w2 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ F3 k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0751w2(F3 f3, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = f3;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C0751w2(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0751w2) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object obj2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            this.j = 1;
            G3 g3 = G3.b;
            androidx.work.impl.model.t tVar = this.k.b;
            Object objC = AbstractC0646j.c(tVar, g3, ((androidx.compose.runtime.F0) tVar.k).i(), this);
            if (objC != obj2) {
                objC = Unit.a;
            }
            if (objC == obj2) {
                return obj2;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        return Unit.a;
    }
}

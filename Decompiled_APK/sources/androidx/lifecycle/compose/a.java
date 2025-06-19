package androidx.lifecycle.compose;

import androidx.compose.runtime.C0807l0;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.a0;

/* loaded from: classes.dex */
public final class a extends i implements Function2 {
    public int j;
    public final /* synthetic */ a0 k;
    public final /* synthetic */ C0807l0 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(a0 a0Var, C0807l0 c0807l0, h hVar) {
        super(2, hVar);
        this.k = a0Var;
        this.l = c0807l0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new a(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            androidx.compose.material.navigation.e eVar = new androidx.compose.material.navigation.e(this.l, 4);
            this.j = 1;
            if (this.k.b(eVar, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}

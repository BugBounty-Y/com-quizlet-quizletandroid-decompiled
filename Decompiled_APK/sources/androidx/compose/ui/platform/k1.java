package androidx.compose.ui.platform;

import androidx.compose.foundation.text.input.internal.C0496b;
import kotlin.KotlinNothingValueException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class k1 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ kotlinx.coroutines.flow.q0 k;
    public final /* synthetic */ C0980z0 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k1(kotlinx.coroutines.flow.q0 q0Var, C0980z0 c0980z0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = q0Var;
        this.l = c0980z0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new k1(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((k1) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
        return kotlin.coroutines.intrinsics.a.a;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            C0496b c0496b = new C0496b(this.l, 1);
            this.j = 1;
            if (this.k.b(c0496b, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        throw new KotlinNothingValueException();
    }
}

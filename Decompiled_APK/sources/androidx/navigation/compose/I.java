package androidx.navigation.compose;

import androidx.compose.animation.core.C0247i0;
import androidx.compose.runtime.F0;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.glance.appwidget.protobuf.Z;
import androidx.navigation.C1291m;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class I extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C0247i0 k;
    public final /* synthetic */ InterfaceC0773a0 l;
    public final /* synthetic */ F0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public I(C0247i0 c0247i0, InterfaceC0773a0 interfaceC0773a0, F0 f0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c0247i0;
        this.l = interfaceC0773a0;
        this.m = f0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new I(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((I) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            C1291m c1291m = (C1291m) ((List) this.l.getValue()).get(((List) r4.getValue()).size() - 2);
            float fI = this.m.i();
            this.j = 1;
            if (this.k.b0(fI, c1291m, this) == aVar) {
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

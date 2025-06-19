package kotlinx.coroutines.flow.internal;

import androidx.glance.appwidget.protobuf.Z;
import androidx.paging.C1304a0;
import java.util.concurrent.atomic.AtomicInteger;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC4992i;

/* loaded from: classes3.dex */
public final class o extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ InterfaceC4992i[] k;
    public final /* synthetic */ int l;
    public final /* synthetic */ AtomicInteger m;
    public final /* synthetic */ kotlinx.coroutines.channels.h n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public o(InterfaceC4992i[] interfaceC4992iArr, int i, AtomicInteger atomicInteger, kotlinx.coroutines.channels.h hVar, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.k = interfaceC4992iArr;
        this.l = i;
        this.m = atomicInteger;
        this.n = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new o(this.k, this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((o) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        AtomicInteger atomicInteger = this.m;
        kotlinx.coroutines.channels.h hVar = this.n;
        try {
            if (i == 0) {
                Z.e(obj);
                InterfaceC4992i[] interfaceC4992iArr = this.k;
                int i2 = this.l;
                InterfaceC4992i interfaceC4992i = interfaceC4992iArr[i2];
                C1304a0 c1304a0 = new C1304a0(hVar, i2, 1);
                this.j = 1;
                if (interfaceC4992i.b(c1304a0, this) == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
            if (atomicInteger.decrementAndGet() == 0) {
                hVar.i(null);
            }
            return Unit.a;
        } finally {
            if (atomicInteger.decrementAndGet() == 0) {
                hVar.i(null);
            }
        }
    }
}

package kotlinx.coroutines.flow;

import com.android.billingclient.api.C1472a;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlinx.coroutines.flow.internal.AbstractC4994b;

/* renamed from: kotlinx.coroutines.flow.n, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5006n extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public int j;
    public final /* synthetic */ InterfaceC5002j k;
    public final /* synthetic */ kotlin.jvm.internal.J l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C5006n(kotlin.coroutines.h hVar, kotlin.jvm.internal.J j, InterfaceC5002j interfaceC5002j) {
        super(1, hVar);
        this.k = interfaceC5002j;
        this.l = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        return new C5006n(hVar, this.l, this.k);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((C5006n) create((kotlin.coroutines.h) obj)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        kotlin.jvm.internal.J j = this.l;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            C1472a c1472a = AbstractC4994b.b;
            Object obj2 = j.a;
            if (obj2 == c1472a) {
                obj2 = null;
            }
            this.j = 1;
            if (this.k.emit(obj2, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        j.a = null;
        return Unit.a;
    }
}

package androidx.compose.foundation.text.input.internal;

import androidx.glance.appwidget.protobuf.Z;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.InterfaceC5025j0;
import kotlinx.coroutines.y0;

/* loaded from: classes.dex */
public final class m extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ n k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(n nVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = nVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        m mVar = new m(this.k, hVar);
        mVar.j = obj;
        return mVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((m) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        boolean z;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        kotlinx.coroutines.C c = (kotlinx.coroutines.C) this.j;
        n nVar = this.k;
        InterfaceC5025j0 interfaceC5025j0 = (InterfaceC5025j0) nVar.a.getAndSet(null);
        AtomicReference atomicReference = nVar.a;
        y0 y0VarA = kotlinx.coroutines.E.A(c, null, null, new l(interfaceC5025j0, nVar, null), 3);
        while (true) {
            if (atomicReference.compareAndSet(null, y0VarA)) {
                z = true;
                break;
            }
            if (atomicReference.get() != null) {
                z = false;
                break;
            }
        }
        return Boolean.valueOf(z);
    }
}

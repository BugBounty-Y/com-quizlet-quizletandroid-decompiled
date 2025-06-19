package kotlinx.coroutines.flow;

import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.internal.AbstractC4998f;

/* renamed from: kotlinx.coroutines.flow.e, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public class C4988e extends AbstractC4998f {
    public final kotlin.coroutines.jvm.internal.i d;

    /* JADX WARN: Multi-variable type inference failed */
    public C4988e(Function2 function2, CoroutineContext coroutineContext, int i, kotlinx.coroutines.channels.a aVar) {
        super(coroutineContext, i, aVar);
        this.d = (kotlin.coroutines.jvm.internal.i) function2;
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    @Override // kotlinx.coroutines.flow.internal.AbstractC4998f
    public Object e(kotlinx.coroutines.channels.u uVar, kotlin.coroutines.h hVar) {
        Object objInvoke = this.d.invoke(uVar, hVar);
        return objInvoke == kotlin.coroutines.intrinsics.a.a ? objInvoke : Unit.a;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    @Override // kotlinx.coroutines.flow.internal.AbstractC4998f
    public AbstractC4998f f(CoroutineContext coroutineContext, int i, kotlinx.coroutines.channels.a aVar) {
        return new C4988e(this.d, coroutineContext, i, aVar);
    }

    @Override // kotlinx.coroutines.flow.internal.AbstractC4998f
    public final String toString() {
        return "block[" + this.d + "] -> " + super.toString();
    }
}

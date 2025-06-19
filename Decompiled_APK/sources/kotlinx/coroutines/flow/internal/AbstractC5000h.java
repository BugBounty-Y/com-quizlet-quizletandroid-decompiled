package kotlinx.coroutines.flow.internal;

import androidx.compose.animation.C0297y;
import com.quizlet.ui.compose.C4830x;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5038w;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* renamed from: kotlinx.coroutines.flow.internal.h, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC5000h extends AbstractC4998f {
    public final InterfaceC4992i d;

    public AbstractC5000h(int i, CoroutineContext coroutineContext, kotlinx.coroutines.channels.a aVar, InterfaceC4992i interfaceC4992i) {
        super(coroutineContext, i, aVar);
        this.d = interfaceC4992i;
    }

    @Override // kotlinx.coroutines.flow.internal.AbstractC4998f, kotlinx.coroutines.flow.InterfaceC4992i
    public final Object b(InterfaceC5002j interfaceC5002j, kotlin.coroutines.h hVar) {
        if (this.b == -3) {
            CoroutineContext context = hVar.getContext();
            Boolean bool = Boolean.FALSE;
            C4830x c4830x = new C4830x(15, (byte) 0);
            CoroutineContext coroutineContext = this.a;
            CoroutineContext coroutineContextPlus = !((Boolean) coroutineContext.fold(bool, c4830x)).booleanValue() ? context.plus(coroutineContext) : AbstractC5038w.a(context, coroutineContext, false);
            if (Intrinsics.b(coroutineContextPlus, context)) {
                Object objK = k(interfaceC5002j, hVar);
                return objK == kotlin.coroutines.intrinsics.a.a ? objK : Unit.a;
            }
            kotlin.coroutines.i iVar = kotlin.coroutines.j.a1;
            if (Intrinsics.b(coroutineContextPlus.get(iVar), context.get(iVar))) {
                CoroutineContext context2 = hVar.getContext();
                if (!(interfaceC5002j instanceof F) && !(interfaceC5002j instanceof B)) {
                    interfaceC5002j = new C0297y(interfaceC5002j, context2);
                }
                Object objC = AbstractC4994b.c(coroutineContextPlus, interfaceC5002j, kotlinx.coroutines.internal.t.b(coroutineContextPlus), new C4999g(this, null), hVar);
                return objC == kotlin.coroutines.intrinsics.a.a ? objC : Unit.a;
            }
        }
        Object objB = super.b(interfaceC5002j, hVar);
        return objB == kotlin.coroutines.intrinsics.a.a ? objB : Unit.a;
    }

    @Override // kotlinx.coroutines.flow.internal.AbstractC4998f
    public final Object e(kotlinx.coroutines.channels.u uVar, kotlin.coroutines.h hVar) {
        Object objK = k(new F(uVar), hVar);
        return objK == kotlin.coroutines.intrinsics.a.a ? objK : Unit.a;
    }

    public abstract Object k(InterfaceC5002j interfaceC5002j, kotlin.coroutines.h hVar);

    @Override // kotlinx.coroutines.flow.internal.AbstractC4998f
    public final String toString() {
        return this.d + " -> " + super.toString();
    }
}

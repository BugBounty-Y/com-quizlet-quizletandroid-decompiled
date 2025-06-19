package kotlinx.coroutines.flow;

import androidx.compose.animation.C0297y;
import kotlin.Unit;
import kotlinx.coroutines.flow.internal.AbstractC4994b;

/* renamed from: kotlinx.coroutines.flow.g, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4990g implements InterfaceC4992i {
    public final InterfaceC4992i a;

    public C4990g(InterfaceC4992i interfaceC4992i) {
        this.a = interfaceC4992i;
    }

    @Override // kotlinx.coroutines.flow.InterfaceC4992i
    public final Object b(InterfaceC5002j interfaceC5002j, kotlin.coroutines.h hVar) {
        kotlin.jvm.internal.J j = new kotlin.jvm.internal.J();
        j.a = AbstractC4994b.b;
        Object objB = this.a.b(new C0297y(this, j, interfaceC5002j, 9), hVar);
        return objB == kotlin.coroutines.intrinsics.a.a ? objB : Unit.a;
    }
}

package androidx.compose.foundation.interaction;

import kotlin.Unit;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes.dex */
public final class m implements l {
    public final d0 a = e0.b(0, 16, kotlinx.coroutines.channels.a.b, 1);

    @Override // androidx.compose.foundation.interaction.l
    public final boolean a(j jVar) {
        return this.a.h(jVar);
    }

    @Override // androidx.compose.foundation.interaction.k
    public final InterfaceC4992i b() {
        return this.a;
    }

    @Override // androidx.compose.foundation.interaction.l
    public final Object c(j jVar, kotlin.coroutines.jvm.internal.c cVar) throws Throwable {
        Object objEmit = this.a.emit(jVar, cVar);
        return objEmit == kotlin.coroutines.intrinsics.a.a ? objEmit : Unit.a;
    }
}

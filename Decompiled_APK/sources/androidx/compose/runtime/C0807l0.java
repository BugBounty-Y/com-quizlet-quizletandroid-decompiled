package androidx.compose.runtime;

import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.runtime.l0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0807l0 implements InterfaceC0773a0, kotlinx.coroutines.C {
    public final CoroutineContext a;
    public final /* synthetic */ InterfaceC0773a0 b;

    public C0807l0(InterfaceC0773a0 interfaceC0773a0, CoroutineContext coroutineContext) {
        this.a = coroutineContext;
        this.b = interfaceC0773a0;
    }

    @Override // androidx.compose.runtime.InterfaceC0773a0
    public final Object component1() {
        return this.b.component1();
    }

    @Override // androidx.compose.runtime.InterfaceC0773a0
    public final Function1 component2() {
        return this.b.component2();
    }

    @Override // kotlinx.coroutines.C
    public final CoroutineContext getCoroutineContext() {
        return this.a;
    }

    @Override // androidx.compose.runtime.W0
    public final Object getValue() {
        return this.b.getValue();
    }

    @Override // androidx.compose.runtime.InterfaceC0773a0
    public final void setValue(Object obj) {
        this.b.setValue(obj);
    }
}

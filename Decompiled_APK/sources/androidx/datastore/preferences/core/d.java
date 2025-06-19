package androidx.datastore.preferences.core;

import androidx.datastore.core.InterfaceC1076h;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.InterfaceC4992i;

/* loaded from: classes.dex */
public final class d implements InterfaceC1076h {
    public final InterfaceC1076h a;

    public d(InterfaceC1076h delegate) {
        Intrinsics.checkNotNullParameter(delegate, "delegate");
        this.a = delegate;
    }

    @Override // androidx.datastore.core.InterfaceC1076h
    public final Object a(Function2 function2, kotlin.coroutines.h hVar) {
        return this.a.a(new c(function2, null), hVar);
    }

    @Override // androidx.datastore.core.InterfaceC1076h
    public final InterfaceC4992i getData() {
        return this.a.getData();
    }
}

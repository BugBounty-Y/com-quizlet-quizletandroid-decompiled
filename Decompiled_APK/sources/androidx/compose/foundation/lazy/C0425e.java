package androidx.compose.foundation.lazy;

import androidx.compose.foundation.lazy.layout.InterfaceC0447t;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.foundation.lazy.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0425e implements InterfaceC0447t {
    public final kotlin.jvm.internal.r a;
    public final Function1 b;
    public final androidx.compose.runtime.internal.d c;

    /* JADX WARN: Multi-variable type inference failed */
    public C0425e(Function1 function1, Function1 function12, androidx.compose.runtime.internal.d dVar) {
        this.a = (kotlin.jvm.internal.r) function1;
        this.b = function12;
        this.c = dVar;
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // androidx.compose.foundation.lazy.layout.InterfaceC0447t
    public final Function1 getKey() {
        return this.a;
    }

    @Override // androidx.compose.foundation.lazy.layout.InterfaceC0447t
    public final Function1 getType() {
        return this.b;
    }
}

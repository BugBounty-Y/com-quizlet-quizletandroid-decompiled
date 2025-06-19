package androidx.compose.ui.text;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class B implements androidx.compose.runtime.saveable.l {
    public final /* synthetic */ kotlin.jvm.internal.r a;
    public final /* synthetic */ kotlin.jvm.internal.r b;

    /* JADX WARN: Multi-variable type inference failed */
    public B(Function2 function2, Function1 function1) {
        this.a = (kotlin.jvm.internal.r) function2;
        this.b = (kotlin.jvm.internal.r) function1;
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [kotlin.jvm.functions.Function2, kotlin.jvm.internal.r] */
    @Override // androidx.compose.runtime.saveable.l
    public final Object a(androidx.compose.runtime.saveable.b bVar, Object obj) {
        return this.a.invoke(bVar, obj);
    }
}

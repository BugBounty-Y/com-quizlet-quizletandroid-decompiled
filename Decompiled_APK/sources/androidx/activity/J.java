package androidx.activity;

import kotlin.collections.C4927s;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class J implements InterfaceC0031c {
    public final D a;
    public final /* synthetic */ L b;

    public J(L l, D onBackPressedCallback) {
        Intrinsics.checkNotNullParameter(onBackPressedCallback, "onBackPressedCallback");
        this.b = l;
        this.a = onBackPressedCallback;
    }

    /* JADX WARN: Type inference failed for: r0v3, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.o] */
    @Override // androidx.activity.InterfaceC0031c
    public final void cancel() {
        L l = this.b;
        C4927s c4927s = l.b;
        D d = this.a;
        c4927s.remove(d);
        if (Intrinsics.b(l.c, d)) {
            d.a();
            l.c = null;
        }
        d.getClass();
        Intrinsics.checkNotNullParameter(this, "cancellable");
        d.b.remove(this);
        ?? r0 = d.c;
        if (r0 != 0) {
            r0.invoke();
        }
        d.c = null;
    }
}

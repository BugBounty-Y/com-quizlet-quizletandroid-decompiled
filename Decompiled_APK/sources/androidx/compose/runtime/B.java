package androidx.compose.runtime;

import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class B extends AbstractC0809m0 {
    public final /* synthetic */ int b = 1;
    public final Object c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public B(Function0 function0) {
        super(function0);
        V v = V.f;
        this.c = v;
    }

    @Override // androidx.compose.runtime.AbstractC0809m0
    public final C0811n0 a(Object obj) {
        switch (this.b) {
            case 0:
                return new C0811n0(this, obj, obj == null, null, true);
            default:
                return new C0811n0(this, obj, obj == null, (M0) this.c, true);
        }
    }

    @Override // androidx.compose.runtime.AbstractC0809m0
    public Z0 b() {
        switch (this.b) {
            case 0:
                return (C) this.c;
            default:
                return super.b();
        }
    }

    public B(Function1 function1) {
        super(A.a);
        this.c = new C(function1);
    }
}

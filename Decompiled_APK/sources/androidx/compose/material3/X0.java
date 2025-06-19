package androidx.compose.material3;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class X0 extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.foundation.lazy.grid.A b;
    public final /* synthetic */ kotlinx.coroutines.C c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ X0(androidx.compose.foundation.lazy.grid.A a, kotlinx.coroutines.C c, int i) {
        super(0);
        this.a = i;
        this.b = a;
        this.c = c;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        boolean z;
        boolean z2;
        switch (this.a) {
            case 0:
                androidx.compose.foundation.lazy.grid.A a = this.b;
                if (a.d()) {
                    kotlinx.coroutines.E.A(this.c, null, null, new W0(a, null), 3);
                    z = true;
                } else {
                    z = false;
                }
                return Boolean.valueOf(z);
            default:
                androidx.compose.foundation.lazy.grid.A a2 = this.b;
                if (a2.b()) {
                    kotlinx.coroutines.E.A(this.c, null, null, new Y0(a2, null), 3);
                    z2 = true;
                } else {
                    z2 = false;
                }
                return Boolean.valueOf(z2);
        }
    }
}

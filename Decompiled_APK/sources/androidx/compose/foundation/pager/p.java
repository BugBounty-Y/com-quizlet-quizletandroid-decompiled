package androidx.compose.foundation.pager;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class p extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ C0466e b;
    public final /* synthetic */ kotlinx.coroutines.C c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ p(C0466e c0466e, kotlinx.coroutines.C c, int i) {
        super(0);
        this.a = i;
        this.b = c0466e;
        this.c = c;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        boolean z;
        boolean z2;
        boolean z3;
        boolean z4;
        switch (this.a) {
            case 0:
                kotlinx.coroutines.C c = this.c;
                C0466e c0466e = this.b;
                if (c0466e.b()) {
                    kotlinx.coroutines.E.A(c, null, null, new r(c0466e, null), 3);
                    z = true;
                } else {
                    z = false;
                }
                return Boolean.valueOf(z);
            case 1:
                kotlinx.coroutines.C c2 = this.c;
                C0466e c0466e2 = this.b;
                if (c0466e2.d()) {
                    kotlinx.coroutines.E.A(c2, null, null, new s(c0466e2, null), 3);
                    z2 = true;
                } else {
                    z2 = false;
                }
                return Boolean.valueOf(z2);
            case 2:
                kotlinx.coroutines.C c3 = this.c;
                C0466e c0466e3 = this.b;
                if (c0466e3.b()) {
                    kotlinx.coroutines.E.A(c3, null, null, new r(c0466e3, null), 3);
                    z3 = true;
                } else {
                    z3 = false;
                }
                return Boolean.valueOf(z3);
            default:
                kotlinx.coroutines.C c4 = this.c;
                C0466e c0466e4 = this.b;
                if (c0466e4.d()) {
                    kotlinx.coroutines.E.A(c4, null, null, new s(c0466e4, null), 3);
                    z4 = true;
                } else {
                    z4 = false;
                }
                return Boolean.valueOf(z4);
        }
    }
}

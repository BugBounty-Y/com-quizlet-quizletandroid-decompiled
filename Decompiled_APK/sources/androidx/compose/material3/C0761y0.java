package androidx.compose.material3;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* renamed from: androidx.compose.material3.y0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0761y0 extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ kotlinx.coroutines.C b;
    public final /* synthetic */ androidx.compose.foundation.lazy.A c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0761y0(kotlinx.coroutines.C c, androidx.compose.foundation.lazy.A a, int i) {
        super(0);
        this.a = i;
        this.b = c;
        this.c = a;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                kotlinx.coroutines.E.A(this.b, null, null, new C0755x0(this.c, null), 3);
                break;
            default:
                kotlinx.coroutines.E.A(this.b, null, null, new C0767z0(this.c, null), 3);
                break;
        }
        return Unit.a;
    }
}

package androidx.compose.foundation.text;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.foundation.text.x, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0549x extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.foundation.text.selection.i0 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0549x(androidx.compose.foundation.text.selection.i0 i0Var, int i) {
        super(1);
        this.a = i;
        this.b = i0Var;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                return new androidx.activity.compose.c(this.b, 6);
            default:
                long j = ((androidx.compose.ui.geometry.b) obj).a;
                this.b.q();
                return Unit.a;
        }
    }
}

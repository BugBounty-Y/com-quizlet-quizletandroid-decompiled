package androidx.compose.ui.platform;

import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.ui.platform.q, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0962q extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.ui.focus.c b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0962q(androidx.compose.ui.focus.c cVar, int i) {
        super(1);
        this.a = i;
        this.b = cVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                Boolean boolF = androidx.compose.ui.focus.a.F((androidx.compose.ui.focus.t) obj, this.b.a);
                return Boolean.valueOf(boolF != null ? boolF.booleanValue() : true);
            default:
                Boolean boolF2 = androidx.compose.ui.focus.a.F((androidx.compose.ui.focus.t) obj, this.b.a);
                return Boolean.valueOf(boolF2 != null ? boolF2.booleanValue() : true);
        }
    }
}

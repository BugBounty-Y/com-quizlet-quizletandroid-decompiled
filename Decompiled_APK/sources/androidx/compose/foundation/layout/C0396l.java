package androidx.compose.foundation.layout;

import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.layout.l, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0396l extends kotlin.jvm.internal.r implements Function2 {
    public static final C0396l b = new C0396l(2, 0);
    public static final C0396l c = new C0396l(2, 1);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0396l(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                return Integer.valueOf(Math.round((1 + (((androidx.compose.ui.unit.k) obj2) != androidx.compose.ui.unit.k.a ? (-1.0f) * (-1) : -1.0f)) * (((Number) obj).intValue() / 2.0f)));
            case 1:
                return Integer.valueOf(((R0) obj).c((androidx.compose.ui.unit.b) obj2));
            default:
                return Integer.valueOf(Math.round((1 + (((androidx.compose.ui.unit.k) obj2) != androidx.compose.ui.unit.k.a ? 1.0f * (-1) : 1.0f)) * ((((Number) obj).intValue() + 0) / 2.0f)));
        }
    }
}

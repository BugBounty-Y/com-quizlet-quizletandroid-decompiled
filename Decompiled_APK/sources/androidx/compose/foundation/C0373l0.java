package androidx.compose.foundation;

import kotlin.jvm.functions.Function0;

/* renamed from: androidx.compose.foundation.l0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0373l0 extends kotlin.jvm.internal.r implements Function0 {
    public static final C0373l0 b = new C0373l0(0, 0);
    public static final C0373l0 c = new C0373l0(0, 1);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0373l0(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return N.a;
            case 1:
                return new A0();
            default:
                return new N0(0);
        }
    }
}

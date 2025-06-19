package androidx.compose.ui.platform;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.ui.platform.n, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0956n extends kotlin.jvm.internal.r implements Function1 {
    public static final C0956n b = new C0956n(1, 0);
    public static final C0956n c = new C0956n(1, 1);
    public static final C0956n d = new C0956n(1, 2);
    public static final C0956n e = new C0956n(1, 3);
    public static final C0956n f = new C0956n(1, 4);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0956n(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                return Unit.a;
            case 1:
                return Boolean.TRUE;
            case 2:
                return Boolean.FALSE;
            case 3:
                return Boolean.valueOf(N.r(obj));
            default:
                if (obj == null) {
                    return Unit.a;
                }
                throw new ClassCastException();
        }
    }
}

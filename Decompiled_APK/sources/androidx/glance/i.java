package androidx.glance;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class i extends kotlin.jvm.internal.r implements Function0 {
    public static final i b = new i(0, 0);
    public static final i c = new i(0, 1);
    public static final i d = new i(0, 2);
    public static final i e = new i(0, 3);
    public static final i f = new i(0, 4);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ i(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return androidx.glance.color.b.B;
            case 1:
                throw new IllegalStateException("No default context");
            case 2:
                throw new IllegalStateException("No default glance id");
            case 3:
                throw new IllegalStateException("No default size");
            default:
                return null;
        }
    }
}

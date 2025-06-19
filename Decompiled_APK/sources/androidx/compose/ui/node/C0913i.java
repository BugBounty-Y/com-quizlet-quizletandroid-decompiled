package androidx.compose.ui.node;

import java.util.LinkedHashMap;
import kotlin.jvm.functions.Function0;

/* renamed from: androidx.compose.ui.node.i, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0913i extends kotlin.jvm.internal.r implements Function0 {
    public static final C0913i b = new C0913i(0, 0);
    public static final C0913i c = new C0913i(0, 1);
    public static final C0913i d = new C0913i(0, 2);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0913i(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return new E(2);
            case 1:
                return new LinkedHashMap();
            default:
                return new E(3);
        }
    }
}

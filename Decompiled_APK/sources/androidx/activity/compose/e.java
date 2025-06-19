package androidx.activity.compose;

import java.util.UUID;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class e extends kotlin.jvm.internal.r implements Function0 {
    public static final e b = new e(0, 0);
    public static final e c = new e(0, 1);
    public static final e d = new e(0, 2);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ e(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return UUID.randomUUID().toString();
            case 1:
                return null;
            default:
                return null;
        }
    }
}

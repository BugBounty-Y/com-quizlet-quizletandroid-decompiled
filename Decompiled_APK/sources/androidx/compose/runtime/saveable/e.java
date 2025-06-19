package androidx.compose.runtime.saveable;

import java.util.Map;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class e extends r implements Function1 {
    public static final e b = new e(1, 0);
    public static final e c = new e(1, 1);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ e(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                return new f((Map) obj);
            default:
                return obj;
        }
    }
}

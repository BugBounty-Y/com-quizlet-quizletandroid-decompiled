package kotlin.random;

import java.util.Random;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends kotlin.random.a {
    public final a c = new a();

    public static final class a extends ThreadLocal {
        @Override // java.lang.ThreadLocal
        public final Object initialValue() {
            return new Random();
        }
    }

    @Override // kotlin.random.a
    public final Random j() {
        Object obj = this.c.get();
        Intrinsics.checkNotNullExpressionValue(obj, "get(...)");
        return (Random) obj;
    }
}

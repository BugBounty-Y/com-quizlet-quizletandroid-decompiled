package kotlinx.serialization.json.internal;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.text.StringsKt;

/* loaded from: classes3.dex */
public abstract class c {
    public static final int a;

    static {
        Object objB;
        try {
            kotlin.p pVar = kotlin.r.b;
            String property = System.getProperty("kotlinx.serialization.json.pool.size");
            objB = property != null ? StringsKt.toIntOrNull(property) : null;
        } catch (Throwable th) {
            kotlin.p pVar2 = kotlin.r.b;
            objB = Z.b(th);
        }
        Integer num = (Integer) (objB instanceof kotlin.q ? null : objB);
        a = num != null ? num.intValue() : 2097152;
    }
}

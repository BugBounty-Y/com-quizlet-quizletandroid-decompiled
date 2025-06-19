package androidx.work;

import java.util.Arrays;
import java.util.Map;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.work.j, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1436j extends kotlin.jvm.internal.r implements Function1 {
    public static final C1436j a = new C1436j(1);

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        Map.Entry entry = (Map.Entry) obj;
        Intrinsics.checkNotNullParameter(entry, "<name for destructuring parameter 0>");
        String str = (String) entry.getKey();
        Object value = entry.getValue();
        StringBuilder sbX = android.support.v4.media.session.a.x(str, " : ");
        if (value instanceof Object[]) {
            value = Arrays.toString((Object[]) value);
            Intrinsics.checkNotNullExpressionValue(value, "toString(this)");
        }
        sbX.append(value);
        return sbX.toString();
    }
}

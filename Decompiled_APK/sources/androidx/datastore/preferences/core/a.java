package androidx.datastore.preferences.core;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.Map;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class a extends r implements Function1 {
    public static final a a = new a(1);

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        String strValueOf;
        Map.Entry entry = (Map.Entry) obj;
        Intrinsics.checkNotNullParameter(entry, "entry");
        Object value = entry.getValue();
        if (value instanceof byte[]) {
            byte[] bArr = (byte[]) value;
            Intrinsics.checkNotNullParameter(bArr, "<this>");
            Intrinsics.checkNotNullParameter(", ", "separator");
            Intrinsics.checkNotNullParameter("[", "prefix");
            Intrinsics.checkNotNullParameter("]", "postfix");
            Intrinsics.checkNotNullParameter("...", "truncated");
            StringBuilder buffer = new StringBuilder();
            Intrinsics.checkNotNullParameter(bArr, "<this>");
            Intrinsics.checkNotNullParameter(buffer, "buffer");
            Intrinsics.checkNotNullParameter(", ", "separator");
            Intrinsics.checkNotNullParameter("[", "prefix");
            Intrinsics.checkNotNullParameter("]", "postfix");
            Intrinsics.checkNotNullParameter("...", "truncated");
            buffer.append((CharSequence) "[");
            int i = 0;
            for (byte b : bArr) {
                i++;
                if (i > 1) {
                    buffer.append((CharSequence) ", ");
                }
                buffer.append((CharSequence) String.valueOf((int) b));
            }
            buffer.append((CharSequence) "]");
            strValueOf = buffer.toString();
            Intrinsics.checkNotNullExpressionValue(strValueOf, "toString(...)");
        } else {
            strValueOf = String.valueOf(entry.getValue());
        }
        return AbstractC0147y.g(new StringBuilder("  "), ((f) entry.getKey()).a, " = ", strValueOf);
    }
}

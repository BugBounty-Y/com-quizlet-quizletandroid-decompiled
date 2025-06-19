package kotlin.jvm.internal;

import java.util.List;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class Q implements kotlin.reflect.p {

    @NotNull
    public static final P c = new P(null);
    public final C4950i a;
    public volatile List b;

    public Q(C4950i c4950i) {
        kotlin.reflect.s variance = kotlin.reflect.s.a;
        Intrinsics.checkNotNullParameter("PluginConfigT", "name");
        Intrinsics.checkNotNullParameter(variance, "variance");
        this.a = c4950i;
    }

    public final boolean equals(Object obj) {
        if (obj instanceof Q) {
            return this.a.equals(((Q) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return (this.a.hashCode() * 31) + 749883007;
    }

    public final String toString() {
        c.getClass();
        Intrinsics.checkNotNullParameter(this, "typeParameter");
        StringBuilder sb = new StringBuilder();
        kotlin.reflect.s sVar = kotlin.reflect.s.a;
        sb.append("PluginConfigT");
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }
}

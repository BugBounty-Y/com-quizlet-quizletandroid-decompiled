package kotlin.text;

import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: kotlin.text.j, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4971j {

    @NotNull
    public static final C4970i b = new C4970i(null);
    public static final C4971j c = new C4971j();
    public final boolean a;

    public C4971j() {
        Intrinsics.checkNotNullParameter("", "prefix");
        Intrinsics.checkNotNullParameter("", "suffix");
        this.a = true;
        if (J.a("")) {
            return;
        }
        J.a("");
    }

    public final void a(String indent, StringBuilder sb) {
        Intrinsics.checkNotNullParameter(sb, "sb");
        Intrinsics.checkNotNullParameter(indent, "indent");
        sb.append(indent);
        sb.append("prefix = \"");
        sb.append("");
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append("\",");
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append('\n');
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append(indent);
        sb.append("suffix = \"");
        sb.append("");
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append("\",");
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append('\n');
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append(indent);
        sb.append("removeLeadingZeros = ");
        sb.append(false);
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append(',');
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append('\n');
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append(indent);
        sb.append("minLength = ");
        sb.append(1);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("NumberHexFormat(");
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append('\n');
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        a("    ", sb);
        sb.append('\n');
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append(")");
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }
}

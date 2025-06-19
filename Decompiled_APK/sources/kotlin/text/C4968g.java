package kotlin.text;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: kotlin.text.g, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4968g {

    @NotNull
    public static final C4967f a = new C4967f(null);
    public static final C4968g b;

    static {
        Intrinsics.checkNotNullParameter("  ", "groupSeparator");
        Intrinsics.checkNotNullParameter("", "byteSeparator");
        Intrinsics.checkNotNullParameter("", "bytePrefix");
        Intrinsics.checkNotNullParameter("", "byteSuffix");
        C4968g c4968g = new C4968g();
        if (!J.a("  ") && !J.a("") && !J.a("")) {
            J.a("");
        }
        b = c4968g;
    }

    public final void a(String indent, StringBuilder sb) {
        Intrinsics.checkNotNullParameter(sb, "sb");
        Intrinsics.checkNotNullParameter(indent, "indent");
        sb.append(indent);
        sb.append("bytesPerLine = ");
        sb.append(SubsamplingScaleImageView.TILE_SIZE_AUTO);
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append(",");
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append('\n');
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append(indent);
        sb.append("bytesPerGroup = ");
        sb.append(SubsamplingScaleImageView.TILE_SIZE_AUTO);
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append(",");
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append('\n');
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append(indent);
        sb.append("groupSeparator = \"");
        sb.append("  ");
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append("\",");
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append('\n');
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append(indent);
        sb.append("byteSeparator = \"");
        sb.append("");
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append("\",");
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append('\n');
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append(indent);
        sb.append("bytePrefix = \"");
        sb.append("");
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append("\",");
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append('\n');
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append(indent);
        sb.append("byteSuffix = \"");
        sb.append("");
        sb.append("\"");
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("BytesHexFormat(");
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

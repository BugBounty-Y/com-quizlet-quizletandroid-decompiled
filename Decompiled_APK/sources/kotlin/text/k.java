package kotlin.text;

import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class k {

    @NotNull
    public static final C4969h d = new C4969h(null);
    public static final k e;
    public final boolean a;
    public final C4968g b;
    public final C4971j c;

    static {
        C4967f c4967f = C4968g.a;
        c4967f.getClass();
        C4968g c4968g = C4968g.b;
        C4970i c4970i = C4971j.b;
        c4970i.getClass();
        C4971j c4971j = C4971j.c;
        e = new k(false, c4968g, c4971j);
        c4967f.getClass();
        c4970i.getClass();
        new k(true, c4968g, c4971j);
    }

    public k(boolean z, C4968g bytes, C4971j number) {
        Intrinsics.checkNotNullParameter(bytes, "bytes");
        Intrinsics.checkNotNullParameter(number, "number");
        this.a = z;
        this.b = bytes;
        this.c = number;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("HexFormat(");
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append('\n');
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append("    upperCase = ");
        sb.append(this.a);
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append(",");
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append('\n');
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append("    bytes = BytesHexFormat(");
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append('\n');
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        this.b.a("        ", sb);
        sb.append('\n');
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append("    ),");
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append('\n');
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append("    number = NumberHexFormat(");
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append('\n');
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        this.c.a("        ", sb);
        sb.append('\n');
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append("    )");
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append('\n');
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        sb.append(")");
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }
}

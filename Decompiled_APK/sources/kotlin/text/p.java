package kotlin.text;

import java.io.Serializable;
import java.util.regex.Pattern;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class p implements Serializable {

    @NotNull
    public static final o c = new o(null);
    public final String a;
    public final int b;

    public p(String pattern, int i) {
        Intrinsics.checkNotNullParameter(pattern, "pattern");
        this.a = pattern;
        this.b = i;
    }

    private final Object readResolve() {
        Pattern patternCompile = Pattern.compile(this.a, this.b);
        Intrinsics.checkNotNullExpressionValue(patternCompile, "compile(...)");
        return new Regex(patternCompile);
    }
}

package kotlin.text;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class Regex implements Serializable {

    @NotNull
    public static final n b = new n(null);
    public final Pattern a;

    public Regex(Pattern nativePattern) {
        Intrinsics.checkNotNullParameter(nativePattern, "nativePattern");
        this.a = nativePattern;
    }

    public static kotlin.sequences.g c(Regex regex, String input) {
        regex.getClass();
        Intrinsics.checkNotNullParameter(input, "input");
        if (input.length() < 0) {
            StringBuilder sbV = android.support.v4.media.session.a.v(0, "Start index out of bounds: ", ", input length: ");
            sbV.append(input.length());
            throw new IndexOutOfBoundsException(sbV.toString());
        }
        q seedFunction = new q(regex, input);
        r nextFunction = r.a;
        Intrinsics.checkNotNullParameter(seedFunction, "seedFunction");
        Intrinsics.checkNotNullParameter(nextFunction, "nextFunction");
        return new kotlin.sequences.g(seedFunction, nextFunction);
    }

    private final Object writeReplace() {
        Pattern pattern = this.a;
        String strPattern = pattern.pattern();
        Intrinsics.checkNotNullExpressionValue(strPattern, "pattern(...)");
        return new p(strPattern, pattern.flags());
    }

    public final boolean a(CharSequence input) {
        Intrinsics.checkNotNullParameter(input, "input");
        return this.a.matcher(input).find();
    }

    public final m b(CharSequence input) {
        Intrinsics.checkNotNullParameter(input, "input");
        Matcher matcher = this.a.matcher(input);
        Intrinsics.checkNotNullExpressionValue(matcher, "matcher(...)");
        if (matcher.find(0)) {
            return new m(matcher, input);
        }
        return null;
    }

    public final m d(String input) {
        Intrinsics.checkNotNullParameter(input, "input");
        Matcher matcher = this.a.matcher(input);
        Intrinsics.checkNotNullExpressionValue(matcher, "matcher(...)");
        if (matcher.matches()) {
            return new m(matcher, input);
        }
        return null;
    }

    public final boolean e(CharSequence input) {
        Intrinsics.checkNotNullParameter(input, "input");
        return this.a.matcher(input).matches();
    }

    public final String f(String input, Function1 transform) {
        Intrinsics.checkNotNullParameter(input, "input");
        Intrinsics.checkNotNullParameter(transform, "transform");
        m mVarB = b(input);
        if (mVarB == null) {
            return input.toString();
        }
        int length = input.length();
        StringBuilder sb = new StringBuilder(length);
        int i = 0;
        do {
            sb.append((CharSequence) input, i, mVarB.c().a);
            sb.append((CharSequence) transform.invoke(mVarB));
            i = mVarB.c().b + 1;
            mVarB = mVarB.next();
            if (i >= length) {
                break;
            }
        } while (mVarB != null);
        if (i < length) {
            sb.append((CharSequence) input, i, length);
        }
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }

    public final List g(int i, String input) {
        Intrinsics.checkNotNullParameter(input, "input");
        StringsKt__StringsKt.y(i);
        Matcher matcher = this.a.matcher(input);
        if (i == 1 || !matcher.find()) {
            return kotlin.collections.A.b(input.toString());
        }
        int i2 = 10;
        if (i > 0 && i <= 10) {
            i2 = i;
        }
        ArrayList arrayList = new ArrayList(i2);
        int i3 = i - 1;
        int iEnd = 0;
        do {
            arrayList.add(input.subSequence(iEnd, matcher.start()).toString());
            iEnd = matcher.end();
            if (i3 >= 0 && arrayList.size() == i3) {
                break;
            }
        } while (matcher.find());
        arrayList.add(input.subSequence(iEnd, input.length()).toString());
        return arrayList;
    }

    @NotNull
    public final String replace(@NotNull CharSequence input, @NotNull String replacement) {
        Intrinsics.checkNotNullParameter(input, "input");
        Intrinsics.checkNotNullParameter(replacement, "replacement");
        String strReplaceAll = this.a.matcher(input).replaceAll(replacement);
        Intrinsics.checkNotNullExpressionValue(strReplaceAll, "replaceAll(...)");
        return strReplaceAll;
    }

    public final String toString() {
        String string = this.a.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public Regex(@NotNull String pattern) {
        Intrinsics.checkNotNullParameter(pattern, "pattern");
        Pattern patternCompile = Pattern.compile(pattern);
        Intrinsics.checkNotNullExpressionValue(patternCompile, "compile(...)");
        this(patternCompile);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public Regex(String pattern, s option) {
        Intrinsics.checkNotNullParameter(pattern, "pattern");
        Intrinsics.checkNotNullParameter(option, "option");
        n nVar = b;
        int i = option.a;
        nVar.getClass();
        Pattern patternCompile = Pattern.compile(pattern, (i & 2) != 0 ? i | 64 : i);
        Intrinsics.checkNotNullExpressionValue(patternCompile, "compile(...)");
        this(patternCompile);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public Regex(Set options) {
        Intrinsics.checkNotNullParameter("^[A-Z0-9._%+-]+@[A-Z0-9.-]+.[A-Z]{2,}$", "pattern");
        Intrinsics.checkNotNullParameter(options, "options");
        n nVar = b;
        Iterator it2 = options.iterator();
        int i = 0;
        while (it2.hasNext()) {
            i |= ((s) ((InterfaceC4965d) it2.next())).a;
        }
        nVar.getClass();
        Pattern patternCompile = Pattern.compile("^[A-Z0-9._%+-]+@[A-Z0-9.-]+.[A-Z]{2,}$", (i & 2) != 0 ? i | 64 : i);
        Intrinsics.checkNotNullExpressionValue(patternCompile, "compile(...)");
        this(patternCompile);
    }
}

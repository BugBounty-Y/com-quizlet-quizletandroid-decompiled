package kotlin.text;

import java.util.List;
import java.util.regex.Matcher;
import kotlin.collections.W;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;

/* loaded from: classes3.dex */
public final class m implements MatchResult {
    public final Matcher a;
    public final CharSequence b;
    public final androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.m c;
    public W d;

    public m(Matcher matcher, CharSequence input) {
        Intrinsics.checkNotNullParameter(matcher, "matcher");
        Intrinsics.checkNotNullParameter(input, "input");
        this.a = matcher;
        this.b = input;
        this.c = new androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.m(this, 2);
    }

    @Override // kotlin.text.MatchResult
    public final com.quizlet.quizletandroid.k a() {
        return new com.quizlet.quizletandroid.k(this);
    }

    @Override // kotlin.text.MatchResult
    public final List b() {
        if (this.d == null) {
            this.d = new W(this);
        }
        W w = this.d;
        Intrinsics.d(w);
        return w;
    }

    @Override // kotlin.text.MatchResult
    public final IntRange c() {
        Matcher matcher = this.a;
        return kotlin.ranges.l.h(matcher.start(), matcher.end());
    }

    @Override // kotlin.text.MatchResult
    public final String getValue() {
        String strGroup = this.a.group();
        Intrinsics.checkNotNullExpressionValue(strGroup, "group(...)");
        return strGroup;
    }

    @Override // kotlin.text.MatchResult
    public final m next() {
        Matcher matcher = this.a;
        int iEnd = matcher.end() + (matcher.end() == matcher.start() ? 1 : 0);
        CharSequence charSequence = this.b;
        if (iEnd > charSequence.length()) {
            return null;
        }
        Matcher matcher2 = matcher.pattern().matcher(charSequence);
        Intrinsics.checkNotNullExpressionValue(matcher2, "matcher(...)");
        if (matcher2.find(iEnd)) {
            return new m(matcher2, charSequence);
        }
        return null;
    }
}

package assistantMode.questions.generators;

import kotlin.Pair;
import kotlin.collections.V;
import kotlin.text.Regex;

/* loaded from: classes.dex */
public abstract class g {
    public static final Regex a = new Regex("^(an|An|a|A)( |\n)$| (a|A|an|An)( |\n)$");
    public static final Regex b = new Regex("(An|an|A|a)");
    public static final Object c = V.f(new Pair("a", "a(n)"), new Pair("an", "a(n)"), new Pair("An", "A(n)"), new Pair("A", "A(n)"));
}

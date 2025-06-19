package grading.core;

import kotlin.text.Regex;
import kotlin.text.s;

/* loaded from: classes3.dex */
public abstract class g {
    public static final Regex a = new Regex("[\\s\\uFEFF\\xA0\\u3000\\u200B-\\u200D]+");
    public static final Regex b = new Regex("[%.,;!¿#$/:\\[\\]_\\\\\"¡]");
    public static final Regex c = new Regex("\\*([^*]+)\\*");
    public static final Regex d = new Regex("^[\\s\\uFEFF\\xA0\\u3000\\u200B-\\u200D]+|[\\s\\uFEFF\\u0240\\u3000\\u200B-\\u200D]+$");
    public static final Regex e = new Regex("(\\s+-+\\s+)");
    public static final Regex f = new Regex("[()]");
    public static final Regex g;
    public static final Regex h;
    public static final Regex i;
    public static final Regex j;
    public static final Regex k;
    public static final Regex[] l;
    public static final Regex[] m;
    public static final Regex n;
    public static final Regex o;
    public static final Regex p;
    public static final Regex q;
    public static final Regex r;
    public static final Regex s;
    public static final Regex t;
    public static final Regex u;

    static {
        new Regex("[(\\[)\\]]");
        g = new Regex("[,;/]");
        h = new Regex("([+&])");
        s sVar = s.b;
        i = new Regex("^(the|a|an) ", sVar);
        j = new Regex("^(la|une|un|le) ", sVar);
        k = new Regex("^(una|la|un|el) ", sVar);
        l = new Regex[]{new Regex("^(la|une) ", sVar), new Regex("^(le|un) ", sVar)};
        m = new Regex[]{new Regex("^(el|un) ", sVar), new Regex("^(la|una) ", sVar)};
        n = new Regex("ß");
        o = new Regex("\\s-");
        p = new Regex("-\\s");
        q = new Regex("\\s=");
        r = new Regex("=\\s");
        s = new Regex("\\d+");
        t = new Regex("(?!\\b)-\\b");
        u = new Regex("\\b-(?!\\b)");
    }
}

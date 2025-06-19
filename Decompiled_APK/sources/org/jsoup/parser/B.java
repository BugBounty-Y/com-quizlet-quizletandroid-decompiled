package org.jsoup.parser;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public abstract class B {
    public static final C5118m a;
    public static final C5129s b;
    public static final C5131t c;
    public static final C5133u d;
    public static final C5135v e;
    public static final C5137w f;
    public static final C5139x g;
    public static final C5141y h;
    public static final C5143z i;
    public static final C5098c j;
    public static final C5100d k;
    public static final C5102e l;
    public static final C5104f m;
    public static final C5106g n;
    public static final C5108h o;
    public static final C5110i p;
    public static final C5112j q;
    public static final C5114k r;
    public static final C5116l s;
    public static final C5120n t;
    public static final C5122o u;
    public static final C5124p v;
    public static final C5126q w;
    public static final String x;
    public static final /* synthetic */ B[] y;

    static {
        C5118m c5118m = new C5118m();
        a = c5118m;
        C5129s c5129s = new C5129s();
        b = c5129s;
        C5131t c5131t = new C5131t();
        c = c5131t;
        C5133u c5133u = new C5133u();
        d = c5133u;
        C5135v c5135v = new C5135v();
        e = c5135v;
        C5137w c5137w = new C5137w();
        f = c5137w;
        C5139x c5139x = new C5139x();
        g = c5139x;
        C5141y c5141y = new C5141y();
        h = c5141y;
        C5143z c5143z = new C5143z();
        i = c5143z;
        C5098c c5098c = new C5098c();
        j = c5098c;
        C5100d c5100d = new C5100d();
        k = c5100d;
        C5102e c5102e = new C5102e();
        l = c5102e;
        C5104f c5104f = new C5104f();
        m = c5104f;
        C5106g c5106g = new C5106g();
        n = c5106g;
        C5108h c5108h = new C5108h();
        o = c5108h;
        C5110i c5110i = new C5110i();
        p = c5110i;
        C5112j c5112j = new C5112j();
        q = c5112j;
        C5114k c5114k = new C5114k();
        r = c5114k;
        C5116l c5116l = new C5116l();
        s = c5116l;
        C5120n c5120n = new C5120n();
        t = c5120n;
        C5122o c5122o = new C5122o();
        u = c5122o;
        C5124p c5124p = new C5124p();
        v = c5124p;
        C5126q c5126q = new C5126q();
        w = c5126q;
        y = new B[]{c5118m, c5129s, c5131t, c5133u, c5135v, c5137w, c5139x, c5141y, c5143z, c5098c, c5100d, c5102e, c5104f, c5106g, c5108h, c5110i, c5112j, c5114k, c5116l, c5120n, c5122o, c5124p, c5126q, new B() { // from class: org.jsoup.parser.r
            @Override // org.jsoup.parser.B
            public final boolean c(androidx.sqlite.db.b bVar, C5096b c5096b) {
                return true;
            }
        }};
        x = String.valueOf((char) 0);
    }

    public static boolean a(androidx.sqlite.db.b bVar) {
        if (bVar.b == 5) {
            return org.jsoup.internal.a.d(((G) bVar).c);
        }
        return false;
    }

    public static void b(L l2, C5096b c5096b) {
        c5096b.c.o(e1.e);
        c5096b.m = c5096b.l;
        c5096b.l = h;
        c5096b.y(l2);
    }

    public static B valueOf(String str) {
        return (B) Enum.valueOf(B.class, str);
    }

    public static B[] values() {
        return (B[]) y.clone();
    }

    public abstract boolean c(androidx.sqlite.db.b bVar, C5096b c5096b);
}

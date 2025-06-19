package androidx.webkit;

/* loaded from: classes.dex */
public final class f {
    public final String a;
    public final String b;
    public final e c;

    public f(String str, e eVar) {
        if (str.isEmpty() || str.charAt(0) != '/') {
            throw new IllegalArgumentException("Path should start with a slash '/'.");
        }
        if (!str.endsWith("/")) {
            throw new IllegalArgumentException("Path should end with a slash '/'");
        }
        this.a = "iamcache.braze";
        this.b = str;
        this.c = eVar;
    }
}

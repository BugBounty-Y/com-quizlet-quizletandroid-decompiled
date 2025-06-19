package org.slf4j;

/* loaded from: classes3.dex */
public interface b {
    boolean a();

    boolean b();

    void c(String str, Throwable th);

    boolean d();

    boolean e();

    void error(String str);

    void f(String str);

    boolean g();

    String getName();

    void h(String str, Throwable th);

    void j(String str, Throwable th);

    void k(String str, Throwable th);

    void l(String str, Throwable th);

    void m(String str);

    void n(String str);

    default boolean o(int i) {
        char c;
        if (i == 1) {
            c = '(';
        } else if (i == 2) {
            c = 30;
        } else if (i == 3) {
            c = 20;
        } else if (i == 4) {
            c = '\n';
        } else {
            if (i != 5) {
                throw null;
            }
            c = 0;
        }
        if (c == 0) {
            return g();
        }
        if (c == '\n') {
            return b();
        }
        if (c == 20) {
            return e();
        }
        if (c == 30) {
            return a();
        }
        if (c == '(') {
            return d();
        }
        StringBuilder sb = new StringBuilder("Level [");
        sb.append(i != 1 ? i != 2 ? i != 3 ? i != 4 ? i != 5 ? "null" : "TRACE" : "DEBUG" : "INFO" : "WARN" : "ERROR");
        sb.append("] not recognized.");
        throw new IllegalArgumentException(sb.toString());
    }

    void p(String str, String str2);

    void warn(String str);
}

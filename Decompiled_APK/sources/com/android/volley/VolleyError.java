package com.android.volley;

/* loaded from: classes.dex */
public class VolleyError extends Exception {
    public final h a;
    public long b;

    public VolleyError() {
        this.a = null;
    }

    public VolleyError(h hVar) {
        this.a = hVar;
    }

    public VolleyError(int i) {
        super("Location header does not exists for Redirection");
        this.a = null;
    }

    public VolleyError(Throwable th) {
        super(th);
        this.a = null;
    }
}

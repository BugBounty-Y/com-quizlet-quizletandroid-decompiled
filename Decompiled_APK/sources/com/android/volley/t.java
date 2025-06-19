package com.android.volley;

/* loaded from: classes.dex */
public final class t {
    public final Object a;
    public final a b;
    public final VolleyError c;
    public boolean d;

    public t(Object obj, a aVar) {
        this.d = false;
        this.a = obj;
        this.b = aVar;
        this.c = null;
    }

    public t(VolleyError volleyError) {
        this.d = false;
        this.a = null;
        this.b = null;
        this.c = volleyError;
    }
}

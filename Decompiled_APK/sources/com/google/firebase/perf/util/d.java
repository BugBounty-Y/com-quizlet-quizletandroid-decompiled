package com.google.firebase.perf.util;

import java.util.NoSuchElementException;

/* loaded from: classes2.dex */
public final class d {
    public final Object a;

    public d() {
        this.a = null;
    }

    public final Object a() {
        Object obj = this.a;
        if (obj != null) {
            return obj;
        }
        throw new NoSuchElementException("No value present");
    }

    public final boolean b() {
        return this.a != null;
    }

    public d(Object obj) {
        if (obj != null) {
            this.a = obj;
            return;
        }
        throw new NullPointerException("value for optional is empty.");
    }
}

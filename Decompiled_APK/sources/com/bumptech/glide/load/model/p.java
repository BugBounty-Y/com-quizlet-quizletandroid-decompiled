package com.bumptech.glide.load.model;

import java.util.ArrayDeque;

/* loaded from: classes.dex */
public final class p {
    public static final ArrayDeque b;
    public Object a;

    static {
        char[] cArr = com.bumptech.glide.util.m.a;
        b = new ArrayDeque(0);
    }

    public static p a(Object obj) {
        p pVar;
        ArrayDeque arrayDeque = b;
        synchronized (arrayDeque) {
            pVar = (p) arrayDeque.poll();
        }
        if (pVar == null) {
            pVar = new p();
        }
        pVar.a = obj;
        return pVar;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof p)) {
            return false;
        }
        p pVar = (p) obj;
        pVar.getClass();
        return this.a.equals(pVar.a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }
}

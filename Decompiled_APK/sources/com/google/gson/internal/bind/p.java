package com.google.gson.internal.bind;

import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.util.BitSet;
import java.util.Currency;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicIntegerArray;

/* loaded from: classes2.dex */
public abstract class p {
    public static final m a = new m(Class.class, new com.google.gson.i(new h(12), 2), 0);
    public static final m b = new m(BitSet.class, new com.google.gson.i(new h(21), 2), 0);
    public static final h c;
    public static final n d;
    public static final n e;
    public static final n f;
    public static final n g;
    public static final m h;
    public static final m i;
    public static final m j;
    public static final h k;
    public static final n l;
    public static final h m;
    public static final h n;
    public static final m o;
    public static final m p;
    public static final m q;
    public static final m r;
    public static final m s;
    public static final m t;
    public static final m u;
    public static final m v;
    public static final g w;
    public static final m x;
    public static final m y;
    public static final a z;

    static {
        h hVar = new h(22);
        c = new h(23);
        d = new n(Boolean.TYPE, Boolean.class, hVar);
        e = new n(Byte.TYPE, Byte.class, new h(24));
        f = new n(Short.TYPE, Short.class, new h(25));
        g = new n(Integer.TYPE, Integer.class, new h(26));
        h = new m(AtomicInteger.class, new com.google.gson.i(new h(27), 2), 0);
        i = new m(AtomicBoolean.class, new com.google.gson.i(new h(28), 2), 0);
        j = new m(AtomicIntegerArray.class, new com.google.gson.i(new h(2), 2), 0);
        k = new h(3);
        l = new n(Character.TYPE, Character.class, new h(6));
        h hVar2 = new h(7);
        m = new h(8);
        n = new h(9);
        o = new m(String.class, hVar2, 0);
        p = new m(StringBuilder.class, new h(10), 0);
        q = new m(StringBuffer.class, new h(11), 0);
        r = new m(URL.class, new h(13), 0);
        s = new m(URI.class, new h(14), 0);
        t = new m(InetAddress.class, new h(15), 1);
        u = new m(UUID.class, new h(16), 0);
        v = new m(Currency.class, new com.google.gson.i(new h(17), 2), 0);
        w = new g(new h(18), 1);
        x = new m(Locale.class, new h(19), 0);
        y = new m(com.google.gson.m.class, new h(20), 1);
        z = new a(3);
    }
}

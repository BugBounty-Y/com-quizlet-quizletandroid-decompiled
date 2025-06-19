package com.facebook.appevents.aam;

import java.util.List;
import java.util.concurrent.CopyOnWriteArraySet;

/* loaded from: classes.dex */
public final class c {
    public static final CopyOnWriteArraySet d = new CopyOnWriteArraySet();
    public final String a;
    public final String b;
    public final List c;

    public c(String str, String str2, List list) {
        this.a = str;
        this.b = str2;
        this.c = list;
    }

    public static final /* synthetic */ CopyOnWriteArraySet a() {
        if (com.facebook.internal.instrument.crashshield.a.b(c.class)) {
            return null;
        }
        try {
            return d;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(c.class, th);
            return null;
        }
    }

    public final String b() {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return null;
        }
        try {
            return this.a;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
            return null;
        }
    }
}

package org.slf4j.helpers;

import java.lang.reflect.Method;
import java.util.concurrent.LinkedBlockingQueue;

/* loaded from: classes3.dex */
public final class h implements org.slf4j.b {
    public final String a;
    public volatile org.slf4j.b b;
    public Boolean c;
    public Method d;
    public org.slf4j.event.a e;
    public final LinkedBlockingQueue f;
    public final boolean g;

    public h(String str, LinkedBlockingQueue linkedBlockingQueue, boolean z) {
        this.a = str;
        this.f = linkedBlockingQueue;
        this.g = z;
    }

    @Override // org.slf4j.b
    public final boolean a() {
        return i().a();
    }

    @Override // org.slf4j.b
    public final boolean b() {
        return i().b();
    }

    @Override // org.slf4j.b
    public final void c(String str, Throwable th) {
        i().c(str, th);
    }

    @Override // org.slf4j.b
    public final boolean d() {
        return i().d();
    }

    @Override // org.slf4j.b
    public final boolean e() {
        return i().e();
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return obj != null && h.class == obj.getClass() && this.a.equals(((h) obj).a);
    }

    @Override // org.slf4j.b
    public final void error(String str) {
        i().error(str);
    }

    @Override // org.slf4j.b
    public final void f(String str) {
        i().f(str);
    }

    @Override // org.slf4j.b
    public final boolean g() {
        return i().g();
    }

    @Override // org.slf4j.b
    public final String getName() {
        return this.a;
    }

    @Override // org.slf4j.b
    public final void h(String str, Throwable th) {
        i().h(str, th);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final org.slf4j.b i() {
        if (this.b != null) {
            return this.b;
        }
        if (this.g) {
            return c.b;
        }
        if (this.e == null) {
            org.slf4j.event.a aVar = new org.slf4j.event.a();
            aVar.b = this;
            aVar.a = this.a;
            aVar.c = this.f;
            this.e = aVar;
        }
        return this.e;
    }

    @Override // org.slf4j.b
    public final void j(String str, Throwable th) {
        i().j(str, th);
    }

    @Override // org.slf4j.b
    public final void k(String str, Throwable th) {
        i().k(str, th);
    }

    @Override // org.slf4j.b
    public final void l(String str, Throwable th) {
        i().l(str, th);
    }

    @Override // org.slf4j.b
    public final void m(String str) {
        i().m(str);
    }

    @Override // org.slf4j.b
    public final void n(String str) {
        i().n(str);
    }

    @Override // org.slf4j.b
    public final boolean o(int i) {
        return i().o(i);
    }

    @Override // org.slf4j.b
    public final void p(String str, String str2) {
        i().p(str, str2);
    }

    public final boolean q() {
        Boolean bool = this.c;
        if (bool != null) {
            return bool.booleanValue();
        }
        try {
            this.d = this.b.getClass().getMethod("log", org.slf4j.event.b.class);
            this.c = Boolean.TRUE;
        } catch (NoSuchMethodException unused) {
            this.c = Boolean.FALSE;
        }
        return this.c.booleanValue();
    }

    @Override // org.slf4j.b
    public final void warn(String str) {
        i().warn(str);
    }
}

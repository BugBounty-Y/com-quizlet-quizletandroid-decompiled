package org.slf4j.helpers;

import java.io.ObjectStreamException;
import java.io.Serializable;

/* loaded from: classes3.dex */
public abstract class a implements org.slf4j.b, Serializable {
    @Override // org.slf4j.b
    public final void c(String str, Throwable th) {
        q(1, null);
    }

    @Override // org.slf4j.b
    public final void error(String str) {
        q(1, null);
    }

    @Override // org.slf4j.b
    public final void f(String str) {
        q(4, null);
    }

    @Override // org.slf4j.b
    public final void h(String str, Throwable th) {
        q(3, null);
    }

    @Override // org.slf4j.b
    public final void j(String str, Throwable th) {
        q(2, null);
    }

    @Override // org.slf4j.b
    public final void k(String str, Throwable th) {
        q(5, null);
    }

    @Override // org.slf4j.b
    public final void l(String str, Throwable th) {
        q(4, null);
    }

    @Override // org.slf4j.b
    public final void m(String str) {
        q(3, null);
    }

    @Override // org.slf4j.b
    public final void n(String str) {
        q(5, null);
    }

    @Override // org.slf4j.b
    public final void p(String str, String str2) {
        q(3, new Object[]{str2});
    }

    public abstract void q(int i, Object[] objArr);

    public Object readResolve() throws ObjectStreamException {
        return org.slf4j.d.d(((org.slf4j.event.a) this).a);
    }

    @Override // org.slf4j.b
    public final void warn(String str) {
        q(2, null);
    }
}

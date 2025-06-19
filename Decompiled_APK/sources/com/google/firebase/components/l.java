package com.google.firebase.components;

/* loaded from: classes2.dex */
public final class l implements com.google.firebase.inject.b {
    public static final Object c = new Object();
    public volatile Object a = c;
    public volatile com.google.firebase.inject.b b;

    public l(com.google.firebase.inject.b bVar) {
        this.b = bVar;
    }

    @Override // com.google.firebase.inject.b
    public final Object get() {
        Object obj;
        Object obj2 = this.a;
        Object obj3 = c;
        if (obj2 != obj3) {
            return obj2;
        }
        synchronized (this) {
            try {
                obj = this.a;
                if (obj == obj3) {
                    obj = this.b.get();
                    this.a = obj;
                    this.b = null;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return obj;
    }
}

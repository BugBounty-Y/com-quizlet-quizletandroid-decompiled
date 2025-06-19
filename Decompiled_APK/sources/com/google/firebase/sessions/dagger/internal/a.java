package com.google.firebase.sessions.dagger.internal;

/* loaded from: classes2.dex */
public final class a implements javax.inject.a, com.google.firebase.sessions.dagger.a {
    public static final Object c = new Object();
    public volatile javax.inject.a a;
    public volatile Object b = c;

    public a(javax.inject.a aVar) {
        this.a = aVar;
    }

    public static javax.inject.a a(b bVar) {
        return bVar instanceof a ? bVar : new a(bVar);
    }

    @Override // javax.inject.a
    public final Object get() {
        Object obj;
        Object obj2 = this.b;
        Object obj3 = c;
        if (obj2 != obj3) {
            return obj2;
        }
        synchronized (this) {
            try {
                obj = this.b;
                if (obj == obj3) {
                    obj = this.a.get();
                    Object obj4 = this.b;
                    if (obj4 != obj3 && obj4 != obj) {
                        throw new IllegalStateException("Scoped provider was invoked recursively returning different results: " + obj4 + " & " + obj + ". This is likely due to a circular dependency.");
                    }
                    this.b = obj;
                    this.a = null;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return obj;
    }
}

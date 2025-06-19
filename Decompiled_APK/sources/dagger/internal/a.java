package dagger.internal;

/* loaded from: classes3.dex */
public final class a implements c {
    public static final Object c = new Object();
    public volatile c a;
    public volatile Object b = c;

    public a(c cVar) {
        this.a = cVar;
    }

    public static a a(c cVar) {
        if (cVar instanceof a) {
            return (a) cVar;
        }
        cVar.getClass();
        return new a(cVar);
    }

    public static c b(c cVar) {
        return cVar instanceof a ? cVar : new a(cVar);
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
        }
        return obj;
    }
}

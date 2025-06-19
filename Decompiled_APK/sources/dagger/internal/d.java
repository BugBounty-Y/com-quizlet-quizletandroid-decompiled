package dagger.internal;

/* loaded from: classes3.dex */
public final class d implements c {
    public static final Object c = new Object();
    public volatile c a;
    public volatile Object b;

    public static c a(c cVar) {
        if ((cVar instanceof d) || (cVar instanceof a)) {
            return cVar;
        }
        d dVar = new d();
        dVar.b = c;
        dVar.a = cVar;
        return dVar;
    }

    @Override // javax.inject.a
    public final Object get() {
        Object obj = this.b;
        if (obj != c) {
            return obj;
        }
        c cVar = this.a;
        if (cVar == null) {
            return this.b;
        }
        Object obj2 = cVar.get();
        this.b = obj2;
        this.a = null;
        return obj2;
    }
}

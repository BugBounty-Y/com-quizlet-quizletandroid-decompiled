package com.google.android.datatransport;

/* loaded from: classes2.dex */
public final class a {
    public final Object a;
    public final d b;
    public final b c;

    public a(Object obj, d dVar, b bVar) {
        if (obj == null) {
            throw new NullPointerException("Null payload");
        }
        this.a = obj;
        this.b = dVar;
        this.c = bVar;
    }

    public static a a(Object obj) {
        return new a(obj, d.a, null);
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof a) {
            a aVar = (a) obj;
            aVar.getClass();
            if (this.a.equals(aVar.a) && this.b.equals(aVar.b)) {
                b bVar = aVar.c;
                b bVar2 = this.c;
                if (bVar2 != null ? bVar2.equals(bVar) : bVar == null) {
                    return true;
                }
            }
        }
        return false;
    }

    public final int hashCode() {
        int iHashCode = ((((1000003 * 1000003) ^ this.a.hashCode()) * 1000003) ^ this.b.hashCode()) * 1000003;
        b bVar = this.c;
        return (iHashCode ^ (bVar == null ? 0 : bVar.hashCode())) * 1000003;
    }

    public final String toString() {
        return "Event{code=null, payload=" + this.a + ", priority=" + this.b + ", productData=" + this.c + ", eventContext=null}";
    }
}

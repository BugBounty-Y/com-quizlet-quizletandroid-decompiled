package retrofit2;

import java.lang.reflect.GenericArrayType;
import java.lang.reflect.Type;

/* loaded from: classes3.dex */
public final class O implements GenericArrayType {
    public final Type a;

    public O(Type type) {
        this.a = type;
    }

    public final boolean equals(Object obj) {
        return (obj instanceof GenericArrayType) && S.f(this, (GenericArrayType) obj);
    }

    @Override // java.lang.reflect.GenericArrayType
    public final Type getGenericComponentType() {
        return this.a;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return S.u(this.a) + "[]";
    }
}

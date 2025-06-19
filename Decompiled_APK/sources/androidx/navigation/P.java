package androidx.navigation;

import android.os.Bundle;
import java.io.Serializable;
import kotlin.collections.C4929u;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class P extends S {
    public final Class q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public P(Class type) {
        super(true);
        Intrinsics.checkNotNullParameter(type, "type");
        if (!Serializable.class.isAssignableFrom(type)) {
            throw new IllegalArgumentException((type + " does not implement Serializable.").toString());
        }
        try {
            this.q = Class.forName("[L" + type.getName() + ';');
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    @Override // androidx.navigation.S
    public final Object a(Bundle bundle, String key) {
        Intrinsics.checkNotNullParameter(bundle, "bundle");
        Intrinsics.checkNotNullParameter(key, "key");
        return (Serializable[]) bundle.get(key);
    }

    @Override // androidx.navigation.S
    public final String b() {
        String name = this.q.getName();
        Intrinsics.checkNotNullExpressionValue(name, "getName(...)");
        return name;
    }

    @Override // androidx.navigation.S
    public final Object d(String value) {
        Intrinsics.checkNotNullParameter(value, "value");
        throw new UnsupportedOperationException("Arrays don't support default values.");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r4v1, types: [java.io.Serializable, java.io.Serializable[], java.lang.Object] */
    @Override // androidx.navigation.S
    public final void e(Bundle bundle, String key, Object obj) {
        ?? r4 = (Serializable[]) obj;
        Intrinsics.checkNotNullParameter(bundle, "bundle");
        Intrinsics.checkNotNullParameter(key, "key");
        this.q.cast(r4);
        bundle.putSerializable(key, r4);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || !P.class.equals(obj.getClass())) {
            return false;
        }
        return Intrinsics.b(this.q, ((P) obj).q);
    }

    @Override // androidx.navigation.S
    public final boolean g(Object obj, Object obj2) {
        return C4929u.b((Serializable[]) obj, (Serializable[]) obj2);
    }

    public final int hashCode() {
        return this.q.hashCode();
    }
}

package androidx.navigation;

import android.os.Bundle;
import java.io.Serializable;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public class Q extends S {
    public final Class q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Q(Class type) {
        super(true);
        Intrinsics.checkNotNullParameter(type, "type");
        if (!Serializable.class.isAssignableFrom(type)) {
            throw new IllegalArgumentException((type + " does not implement Serializable.").toString());
        }
        if (!type.isEnum()) {
            this.q = type;
            return;
        }
        throw new IllegalArgumentException((type + " is an Enum. You should use EnumType instead.").toString());
    }

    @Override // androidx.navigation.S
    public final Object a(Bundle bundle, String key) {
        Intrinsics.checkNotNullParameter(bundle, "bundle");
        Intrinsics.checkNotNullParameter(key, "key");
        return (Serializable) bundle.get(key);
    }

    @Override // androidx.navigation.S
    public String b() {
        String name = this.q.getName();
        Intrinsics.checkNotNullExpressionValue(name, "getName(...)");
        return name;
    }

    @Override // androidx.navigation.S
    public final void e(Bundle bundle, String key, Object obj) {
        Serializable value = (Serializable) obj;
        Intrinsics.checkNotNullParameter(bundle, "bundle");
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(value, "value");
        this.q.cast(value);
        bundle.putSerializable(key, value);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Q)) {
            return false;
        }
        return Intrinsics.b(this.q, ((Q) obj).q);
    }

    @Override // androidx.navigation.S
    /* renamed from: h, reason: merged with bridge method [inline-methods] */
    public Serializable d(String value) {
        Intrinsics.checkNotNullParameter(value, "value");
        throw new UnsupportedOperationException("Serializables don't support default values.");
    }

    public final int hashCode() {
        return this.q.hashCode();
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Q(Class type, int i) {
        super(false);
        Intrinsics.checkNotNullParameter(type, "type");
        if (Serializable.class.isAssignableFrom(type)) {
            this.q = type;
            return;
        }
        throw new IllegalArgumentException((type + " does not implement Serializable.").toString());
    }
}

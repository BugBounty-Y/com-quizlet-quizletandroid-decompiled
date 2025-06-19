package androidx.navigation;

import android.os.Bundle;
import android.os.Parcelable;
import java.io.Serializable;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class O extends S {
    public final Class q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public O(Class type) {
        super(true);
        Intrinsics.checkNotNullParameter(type, "type");
        if (Parcelable.class.isAssignableFrom(type) || Serializable.class.isAssignableFrom(type)) {
            this.q = type;
            return;
        }
        throw new IllegalArgumentException((type + " does not implement Parcelable or Serializable.").toString());
    }

    @Override // androidx.navigation.S
    public final Object a(Bundle bundle, String key) {
        Intrinsics.checkNotNullParameter(bundle, "bundle");
        Intrinsics.checkNotNullParameter(key, "key");
        return bundle.get(key);
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
        throw new UnsupportedOperationException("Parcelables don't support default values.");
    }

    @Override // androidx.navigation.S
    public final void e(Bundle bundle, String key, Object obj) {
        Intrinsics.checkNotNullParameter(bundle, "bundle");
        Intrinsics.checkNotNullParameter(key, "key");
        this.q.cast(obj);
        if (obj == null || (obj instanceof Parcelable)) {
            bundle.putParcelable(key, (Parcelable) obj);
        } else if (obj instanceof Serializable) {
            bundle.putSerializable(key, (Serializable) obj);
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || !O.class.equals(obj.getClass())) {
            return false;
        }
        return Intrinsics.b(this.q, ((O) obj).q);
    }

    public final int hashCode() {
        return this.q.hashCode();
    }
}

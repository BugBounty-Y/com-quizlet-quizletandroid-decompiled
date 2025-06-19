package androidx.navigation;

import android.os.Bundle;
import android.os.Parcelable;
import kotlin.collections.C4929u;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class N extends S {
    public final Class q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public N(Class type) {
        super(true);
        Intrinsics.checkNotNullParameter(type, "type");
        if (!Parcelable.class.isAssignableFrom(type)) {
            throw new IllegalArgumentException((type + " does not implement Parcelable.").toString());
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
        return (Parcelable[]) bundle.get(key);
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

    @Override // androidx.navigation.S
    public final void e(Bundle bundle, String key, Object obj) {
        Parcelable[] parcelableArr = (Parcelable[]) obj;
        Intrinsics.checkNotNullParameter(bundle, "bundle");
        Intrinsics.checkNotNullParameter(key, "key");
        this.q.cast(parcelableArr);
        bundle.putParcelableArray(key, parcelableArr);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || !N.class.equals(obj.getClass())) {
            return false;
        }
        return Intrinsics.b(this.q, ((N) obj).q);
    }

    @Override // androidx.navigation.S
    public final boolean g(Object obj, Object obj2) {
        return C4929u.b((Parcelable[]) obj, (Parcelable[]) obj2);
    }

    public final int hashCode() {
        return this.q.hashCode();
    }
}

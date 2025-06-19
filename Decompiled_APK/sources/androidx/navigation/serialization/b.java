package androidx.navigation.serialization;

import android.os.Bundle;
import androidx.navigation.S;
import java.io.Serializable;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;

/* loaded from: classes.dex */
public final class b extends S {
    public final Class q;
    public final Class r;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(Class type) {
        super(true);
        Intrinsics.checkNotNullParameter(type, "type");
        Intrinsics.checkNotNullParameter(type, "type");
        this.q = type;
        if (!Serializable.class.isAssignableFrom(type)) {
            throw new IllegalArgumentException((type + " does not implement Serializable.").toString());
        }
        if (type.isEnum()) {
            this.r = type;
            return;
        }
        throw new IllegalArgumentException((type + " is not an Enum type.").toString());
    }

    @Override // androidx.navigation.S
    public final Object a(Bundle bundle, String key) {
        Intrinsics.checkNotNullParameter(bundle, "bundle");
        Intrinsics.checkNotNullParameter(key, "key");
        Object obj = bundle.get(key);
        if (obj instanceof Serializable) {
            return (Serializable) obj;
        }
        return null;
    }

    @Override // androidx.navigation.S
    public final String b() {
        String name = this.r.getName();
        Intrinsics.checkNotNullExpressionValue(name, "getName(...)");
        return name;
    }

    @Override // androidx.navigation.S
    public final Object d(String value) {
        Intrinsics.checkNotNullParameter(value, "value");
        Object obj = null;
        if (value.equals("null")) {
            return null;
        }
        Class cls = this.r;
        Object[] enumConstants = cls.getEnumConstants();
        Intrinsics.d(enumConstants);
        int length = enumConstants.length;
        int i = 0;
        while (true) {
            if (i >= length) {
                break;
            }
            Object obj2 = enumConstants[i];
            Enum r6 = (Enum) obj2;
            Intrinsics.d(r6);
            if (D.l(r6.name(), value, true)) {
                obj = obj2;
                break;
            }
            i++;
        }
        Enum r1 = (Enum) obj;
        if (r1 != null) {
            return r1;
        }
        StringBuilder sbY = android.support.v4.media.session.a.y("Enum value ", value, " not found for type ");
        sbY.append(cls.getName());
        sbY.append('.');
        throw new IllegalArgumentException(sbY.toString());
    }

    @Override // androidx.navigation.S
    public final void e(Bundle bundle, String key, Object obj) {
        Intrinsics.checkNotNullParameter(bundle, "bundle");
        Intrinsics.checkNotNullParameter(key, "key");
        bundle.putSerializable(key, (Serializable) this.q.cast((Serializable) obj));
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        return Intrinsics.b(this.q, ((b) obj).q);
    }

    public final int hashCode() {
        return this.q.hashCode();
    }
}

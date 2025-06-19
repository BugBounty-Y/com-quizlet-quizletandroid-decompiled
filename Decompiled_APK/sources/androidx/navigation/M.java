package androidx.navigation;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class M extends Q {
    public final Class r;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public M(Class type) {
        super(type, 0);
        Intrinsics.checkNotNullParameter(type, "type");
        if (type.isEnum()) {
            this.r = type;
            return;
        }
        throw new IllegalArgumentException((type + " is not an Enum type.").toString());
    }

    @Override // androidx.navigation.Q, androidx.navigation.S
    public final String b() {
        String name = this.r.getName();
        Intrinsics.checkNotNullExpressionValue(name, "getName(...)");
        return name;
    }

    @Override // androidx.navigation.Q
    /* renamed from: i, reason: merged with bridge method [inline-methods] */
    public final Enum d(String value) {
        Object obj;
        Intrinsics.checkNotNullParameter(value, "value");
        Class cls = this.r;
        Object[] enumConstants = cls.getEnumConstants();
        Intrinsics.checkNotNullExpressionValue(enumConstants, "getEnumConstants(...)");
        int length = enumConstants.length;
        int i = 0;
        while (true) {
            if (i >= length) {
                obj = null;
                break;
            }
            obj = enumConstants[i];
            if (kotlin.text.D.l(((Enum) obj).name(), value, true)) {
                break;
            }
            i++;
        }
        Enum r4 = (Enum) obj;
        if (r4 != null) {
            return r4;
        }
        StringBuilder sbY = android.support.v4.media.session.a.y("Enum value ", value, " not found for type ");
        sbY.append(cls.getName());
        sbY.append('.');
        throw new IllegalArgumentException(sbY.toString());
    }
}

package androidx.room.util;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3327c2;
import java.util.Locale;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes.dex */
public final class a {
    public final String a;
    public final String b;
    public final boolean c;
    public final int d;
    public final String e;
    public final int f;
    public final int g;

    public a(int i, int i2, String name, String type, String str, boolean z) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(type, "type");
        this.a = name;
        this.b = type;
        this.c = z;
        this.d = i;
        this.e = str;
        this.f = i2;
        int i3 = 5;
        if (type != null) {
            Locale US = Locale.US;
            Intrinsics.checkNotNullExpressionValue(US, "US");
            String upperCase = type.toUpperCase(US);
            Intrinsics.checkNotNullExpressionValue(upperCase, "this as java.lang.String).toUpperCase(locale)");
            if (StringsKt.G(upperCase, "INT", false)) {
                i3 = 3;
            } else if (StringsKt.G(upperCase, "CHAR", false) || StringsKt.G(upperCase, "CLOB", false) || StringsKt.G(upperCase, "TEXT", false)) {
                i3 = 2;
            } else if (!StringsKt.G(upperCase, "BLOB", false)) {
                i3 = (StringsKt.G(upperCase, "REAL", false) || StringsKt.G(upperCase, "FLOA", false) || StringsKt.G(upperCase, "DOUB", false)) ? 4 : 1;
            }
        }
        this.g = i3;
    }

    public final boolean equals(Object obj) {
        if (this != obj) {
            if (!(obj instanceof a)) {
                return false;
            }
            a aVar = (a) obj;
            if (this.d != aVar.d) {
                return false;
            }
            if (!Intrinsics.b(this.a, aVar.a) || this.c != aVar.c) {
                return false;
            }
            int i = aVar.f;
            String str = aVar.e;
            String str2 = this.e;
            int i2 = this.f;
            if (i2 == 1 && i == 2 && str2 != null && !AbstractC3327c2.e(str2, str)) {
                return false;
            }
            if (i2 == 2 && i == 1 && str != null && !AbstractC3327c2.e(str, str2)) {
                return false;
            }
            if (i2 != 0 && i2 == i) {
                if (str2 != null) {
                    if (!AbstractC3327c2.e(str2, str)) {
                        return false;
                    }
                } else if (str != null) {
                    return false;
                }
            }
            if (this.g != aVar.g) {
                return false;
            }
        }
        return true;
    }

    public final int hashCode() {
        return (((((this.a.hashCode() * 31) + this.g) * 31) + (this.c ? 1231 : 1237)) * 31) + this.d;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Column{name='");
        sb.append(this.a);
        sb.append("', type='");
        sb.append(this.b);
        sb.append("', affinity='");
        sb.append(this.g);
        sb.append("', notNull=");
        sb.append(this.c);
        sb.append(", primaryKeyPosition=");
        sb.append(this.d);
        sb.append(", defaultValue='");
        String str = this.e;
        if (str == null) {
            str = "undefined";
        }
        return android.support.v4.media.session.a.t(sb, str, "'}");
    }
}

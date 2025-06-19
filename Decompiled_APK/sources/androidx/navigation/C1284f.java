package androidx.navigation;

import android.os.Bundle;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3335e2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3339f2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3343g2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.CharsKt;

/* renamed from: androidx.navigation.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1284f extends S {
    public final /* synthetic */ int q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C1284f(boolean z, int i) {
        super(z);
        this.q = i;
    }

    @Override // androidx.navigation.S
    public final Object a(Bundle source, String key) {
        switch (this.q) {
            case 0:
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                if (!AbstractC3335e2.a(source, key) || AbstractC3335e2.k(source, key)) {
                    return null;
                }
                Intrinsics.checkNotNullParameter(key, "key");
                boolean z = source.getBoolean(key, false);
                if (z || !source.getBoolean(key, true)) {
                    return Boolean.valueOf(z);
                }
                AbstractC3339f2.h(key);
                throw null;
            case 1:
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                return Float.valueOf(AbstractC3335e2.e(source, key));
            case 2:
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                return Integer.valueOf(AbstractC3335e2.f(source, key));
            case 3:
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                return Long.valueOf(AbstractC3335e2.g(source, key));
            default:
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                if (!AbstractC3335e2.a(source, key) || AbstractC3335e2.k(source, key)) {
                    return null;
                }
                Intrinsics.checkNotNullParameter(key, "key");
                String string = source.getString(key);
                if (string != null) {
                    return string;
                }
                AbstractC3339f2.h(key);
                throw null;
        }
    }

    @Override // androidx.navigation.S
    public final String b() {
        switch (this.q) {
            case 0:
                return "boolean";
            case 1:
                return "float";
            case 2:
                return "integer";
            case 3:
                return "long";
            default:
                return "string";
        }
    }

    @Override // androidx.navigation.S
    public final Object d(String value) throws NumberFormatException {
        boolean z;
        int i;
        String strSubstring;
        long j;
        switch (this.q) {
            case 0:
                Intrinsics.checkNotNullParameter(value, "value");
                if (value.equals("true")) {
                    z = true;
                } else {
                    if (!value.equals("false")) {
                        throw new IllegalArgumentException("A boolean NavType only accepts \"true\" or \"false\" values.");
                    }
                    z = false;
                }
                return Boolean.valueOf(z);
            case 1:
                Intrinsics.checkNotNullParameter(value, "value");
                return Float.valueOf(Float.parseFloat(value));
            case 2:
                Intrinsics.checkNotNullParameter(value, "value");
                if (kotlin.text.D.r(value, "0x", false)) {
                    String strSubstring2 = value.substring(2);
                    Intrinsics.checkNotNullExpressionValue(strSubstring2, "substring(...)");
                    i = Integer.parseInt(strSubstring2, CharsKt.checkRadix(16));
                } else {
                    i = Integer.parseInt(value);
                }
                return Integer.valueOf(i);
            case 3:
                Intrinsics.checkNotNullParameter(value, "value");
                if (kotlin.text.D.k(value, "L", false)) {
                    strSubstring = value.substring(0, value.length() - 1);
                    Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
                } else {
                    strSubstring = value;
                }
                if (kotlin.text.D.r(value, "0x", false)) {
                    String strSubstring3 = strSubstring.substring(2);
                    Intrinsics.checkNotNullExpressionValue(strSubstring3, "substring(...)");
                    j = Long.parseLong(strSubstring3, CharsKt.checkRadix(16));
                } else {
                    j = Long.parseLong(strSubstring);
                }
                return Long.valueOf(j);
            default:
                Intrinsics.checkNotNullParameter(value, "value");
                if (Intrinsics.b(value, "null")) {
                    return null;
                }
                return value;
        }
    }

    @Override // androidx.navigation.S
    public final void e(Bundle source, String key, Object obj) {
        switch (this.q) {
            case 0:
                boolean zBooleanValue = ((Boolean) obj).booleanValue();
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                Intrinsics.checkNotNullParameter(key, "key");
                source.putBoolean(key, zBooleanValue);
                break;
            case 1:
                float fFloatValue = ((Number) obj).floatValue();
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                Intrinsics.checkNotNullParameter(key, "key");
                source.putFloat(key, fFloatValue);
                break;
            case 2:
                int iIntValue = ((Number) obj).intValue();
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                Intrinsics.checkNotNullParameter(key, "key");
                source.putInt(key, iIntValue);
                break;
            case 3:
                long jLongValue = ((Number) obj).longValue();
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                Intrinsics.checkNotNullParameter(key, "key");
                source.putLong(key, jLongValue);
                break;
            default:
                String str = (String) obj;
                Intrinsics.checkNotNullParameter(source, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(source, "source");
                if (str == null) {
                    AbstractC3343g2.e(source, key);
                    break;
                } else {
                    AbstractC3343g2.h(key, str, source);
                    break;
                }
        }
    }

    @Override // androidx.navigation.S
    public String f(Object obj) {
        String strB;
        switch (this.q) {
            case 4:
                String str = (String) obj;
                return (str == null || (strB = T.b(str)) == null) ? "null" : strB;
            default:
                return super.f(obj);
        }
    }
}

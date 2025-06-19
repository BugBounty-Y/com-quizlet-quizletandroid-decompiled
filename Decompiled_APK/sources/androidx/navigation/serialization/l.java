package androidx.navigation.serialization;

import android.os.Bundle;
import androidx.navigation.S;
import androidx.navigation.T;
import com.amazon.device.ads.DtbDeviceDataRetriever;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3335e2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3339f2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3343g2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class l extends S {
    public static final l r = new l(false, 0);
    public final /* synthetic */ int q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ l(boolean z, int i) {
        super(z);
        this.q = i;
    }

    @Override // androidx.navigation.S
    public final Object a(Bundle bundle, String key) {
        switch (this.q) {
            case 0:
                Intrinsics.checkNotNullParameter(bundle, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                return null;
            case 1:
                Intrinsics.checkNotNullParameter(bundle, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(bundle, "source");
                if (!AbstractC3335e2.a(bundle, key) || AbstractC3335e2.k(bundle, key)) {
                    return null;
                }
                Intrinsics.checkNotNullParameter(key, "key");
                boolean z = bundle.getBoolean(key, false);
                if (z || !bundle.getBoolean(key, true)) {
                    return Boolean.valueOf(z);
                }
                AbstractC3339f2.h(key);
                throw null;
            case 2:
                Intrinsics.checkNotNullParameter(bundle, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(bundle, "source");
                if (!AbstractC3335e2.a(bundle, key) || AbstractC3335e2.k(bundle, key)) {
                    return null;
                }
                return Double.valueOf(AbstractC3335e2.d(bundle, key));
            case 3:
                Intrinsics.checkNotNullParameter(bundle, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(bundle, "source");
                return Double.valueOf(AbstractC3335e2.d(bundle, key));
            case 4:
                Intrinsics.checkNotNullParameter(bundle, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(bundle, "source");
                if (!AbstractC3335e2.a(bundle, key) || AbstractC3335e2.k(bundle, key)) {
                    return null;
                }
                return Float.valueOf(AbstractC3335e2.e(bundle, key));
            case 5:
                Intrinsics.checkNotNullParameter(bundle, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(bundle, "source");
                if (!AbstractC3335e2.a(bundle, key) || AbstractC3335e2.k(bundle, key)) {
                    return null;
                }
                return Integer.valueOf(AbstractC3335e2.f(bundle, key));
            case 6:
                Intrinsics.checkNotNullParameter(bundle, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(bundle, "source");
                if (!AbstractC3335e2.a(bundle, key) || AbstractC3335e2.k(bundle, key)) {
                    return null;
                }
                return Long.valueOf(AbstractC3335e2.g(bundle, key));
            default:
                Intrinsics.checkNotNullParameter(bundle, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(bundle, "source");
                if (!AbstractC3335e2.a(bundle, key) || AbstractC3335e2.k(bundle, key)) {
                    return "null";
                }
                Intrinsics.checkNotNullParameter(key, "key");
                String string = bundle.getString(key);
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
                return DtbDeviceDataRetriever.ORIENTATION_UNKNOWN;
            case 1:
                return "boolean_nullable";
            case 2:
                return "double_nullable";
            case 3:
                return "double";
            case 4:
                return "float_nullable";
            case 5:
                return "integer_nullable";
            case 6:
                return "long_nullable";
            default:
                return "string_non_nullable";
        }
    }

    @Override // androidx.navigation.S
    public final Object d(String value) {
        switch (this.q) {
            case 0:
                Intrinsics.checkNotNullParameter(value, "value");
                return "null";
            case 1:
                Intrinsics.checkNotNullParameter(value, "value");
                if (value.equals("null")) {
                    return null;
                }
                return (Boolean) S.k.d(value);
            case 2:
                Intrinsics.checkNotNullParameter(value, "value");
                if (value.equals("null")) {
                    return null;
                }
                Intrinsics.checkNotNullParameter(value, "value");
                return Double.valueOf(Double.parseDouble(value));
            case 3:
                Intrinsics.checkNotNullParameter(value, "value");
                return Double.valueOf(Double.parseDouble(value));
            case 4:
                Intrinsics.checkNotNullParameter(value, "value");
                if (value.equals("null")) {
                    return null;
                }
                return (Float) S.h.d(value);
            case 5:
                Intrinsics.checkNotNullParameter(value, "value");
                if (value.equals("null")) {
                    return null;
                }
                return (Integer) S.b.d(value);
            case 6:
                Intrinsics.checkNotNullParameter(value, "value");
                if (value.equals("null")) {
                    return null;
                }
                return (Long) S.e.d(value);
            default:
                Intrinsics.checkNotNullParameter(value, "value");
                return value;
        }
    }

    @Override // androidx.navigation.S
    public final void e(Bundle bundle, String key, Object obj) {
        switch (this.q) {
            case 0:
                Intrinsics.checkNotNullParameter(bundle, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter((String) obj, "value");
                break;
            case 1:
                Boolean bool = (Boolean) obj;
                Intrinsics.checkNotNullParameter(bundle, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                if (bool != null) {
                    S.k.e(bundle, key, bool);
                    break;
                } else {
                    Intrinsics.checkNotNullParameter(bundle, "source");
                    AbstractC3343g2.e(bundle, key);
                    break;
                }
            case 2:
                Double d = (Double) obj;
                Intrinsics.checkNotNullParameter(bundle, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                if (d != null) {
                    double dDoubleValue = d.doubleValue();
                    Intrinsics.checkNotNullParameter(bundle, "bundle");
                    Intrinsics.checkNotNullParameter(key, "key");
                    Intrinsics.checkNotNullParameter(bundle, "source");
                    Intrinsics.checkNotNullParameter(key, "key");
                    bundle.putDouble(key, dDoubleValue);
                    break;
                } else {
                    Intrinsics.checkNotNullParameter(bundle, "source");
                    AbstractC3343g2.e(bundle, key);
                    break;
                }
            case 3:
                double dDoubleValue2 = ((Number) obj).doubleValue();
                Intrinsics.checkNotNullParameter(bundle, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(bundle, "source");
                Intrinsics.checkNotNullParameter(key, "key");
                bundle.putDouble(key, dDoubleValue2);
                break;
            case 4:
                Float f = (Float) obj;
                Intrinsics.checkNotNullParameter(bundle, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                if (f != null) {
                    S.h.e(bundle, key, f);
                    break;
                } else {
                    Intrinsics.checkNotNullParameter(bundle, "source");
                    AbstractC3343g2.e(bundle, key);
                    break;
                }
            case 5:
                Integer num = (Integer) obj;
                Intrinsics.checkNotNullParameter(bundle, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                if (num != null) {
                    S.b.e(bundle, key, num);
                    break;
                } else {
                    Intrinsics.checkNotNullParameter(bundle, "source");
                    AbstractC3343g2.e(bundle, key);
                    break;
                }
            case 6:
                Long l = (Long) obj;
                Intrinsics.checkNotNullParameter(bundle, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                if (l != null) {
                    S.e.e(bundle, key, l);
                    break;
                } else {
                    Intrinsics.checkNotNullParameter(bundle, "source");
                    AbstractC3343g2.e(bundle, key);
                    break;
                }
            default:
                String value = (String) obj;
                Intrinsics.checkNotNullParameter(bundle, "bundle");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(value, "value");
                Intrinsics.checkNotNullParameter(bundle, "source");
                AbstractC3343g2.h(key, value, bundle);
                break;
        }
    }

    @Override // androidx.navigation.S
    public String f(Object obj) {
        switch (this.q) {
            case 7:
                String value = (String) obj;
                Intrinsics.checkNotNullParameter(value, "value");
                return T.b(value);
            default:
                return super.f(obj);
        }
    }
}

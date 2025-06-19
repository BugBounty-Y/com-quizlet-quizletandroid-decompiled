package kotlinx.serialization.json;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.jvm.internal.N;
import kotlin.text.C;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.G;
import kotlinx.serialization.internal.q0;
import kotlinx.serialization.json.internal.JsonDecodingException;

/* loaded from: classes3.dex */
public abstract class l {
    public static final G a;

    static {
        R1.g(N.a);
        a = AbstractC5047c0.a("kotlinx.serialization.json.JsonUnquotedLiteral", q0.a);
    }

    public static final y a(Boolean bool) {
        return new r(bool, false, null);
    }

    public static final y b(Number number) {
        return number == null ? JsonNull.INSTANCE : new r(number, false, null);
    }

    public static final y c(String str) {
        return str == null ? JsonNull.INSTANCE : new r(str, true, null);
    }

    public static final void d(String str, k kVar) {
        throw new IllegalArgumentException("Element " + K.a(kVar.getClass()) + " is not a " + str);
    }

    public static final String e(y yVar) {
        Intrinsics.checkNotNullParameter(yVar, "<this>");
        if (yVar instanceof JsonNull) {
            return null;
        }
        return yVar.a();
    }

    public static final Float f(y yVar) {
        Intrinsics.checkNotNullParameter(yVar, "<this>");
        return C.f(yVar.a());
    }

    public static final Integer g(y yVar) {
        Long lValueOf;
        Intrinsics.checkNotNullParameter(yVar, "<this>");
        try {
            lValueOf = Long.valueOf(i(yVar));
        } catch (JsonDecodingException unused) {
            lValueOf = null;
        }
        if (lValueOf != null) {
            long jLongValue = lValueOf.longValue();
            if (-2147483648L <= jLongValue && jLongValue <= 2147483647L) {
                return Integer.valueOf((int) jLongValue);
            }
        }
        return null;
    }

    public static final y h(k kVar) {
        Intrinsics.checkNotNullParameter(kVar, "<this>");
        y yVar = kVar instanceof y ? (y) kVar : null;
        if (yVar != null) {
            return yVar;
        }
        d("JsonPrimitive", kVar);
        throw null;
    }

    public static final long i(y yVar) {
        Intrinsics.checkNotNullParameter(yVar, "<this>");
        String strA = yVar.a();
        androidx.camera.camera2.internal.concurrent.a aVar = new androidx.camera.camera2.internal.concurrent.a(strA);
        long jK = aVar.k();
        if (aVar.h() == 10) {
            return jK;
        }
        int i = aVar.b;
        int i2 = i - 1;
        androidx.camera.camera2.internal.concurrent.a.r(aVar, android.support.v4.media.session.a.B("Expected input to contain a single valid number, but got '", (i == strA.length() || i2 < 0) ? "EOF" : String.valueOf(strA.charAt(i2)), "' after it"), i2, null, 4);
        throw null;
    }
}

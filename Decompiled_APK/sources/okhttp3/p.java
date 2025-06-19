package okhttp3;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3347h2;
import java.io.EOFException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import kotlin.jvm.internal.Intrinsics;
import okio.C5091h;
import okio.InterfaceC5092i;

/* loaded from: classes3.dex */
public final class p extends F {
    public static final w c;
    public final List a;
    public final List b;

    static {
        Pattern pattern = w.e;
        c = AbstractC3347h2.c("application/x-www-form-urlencoded");
    }

    public p(ArrayList encodedNames, ArrayList encodedValues) {
        Intrinsics.checkNotNullParameter(encodedNames, "encodedNames");
        Intrinsics.checkNotNullParameter(encodedValues, "encodedValues");
        this.a = okhttp3.internal.b.y(encodedNames);
        this.b = okhttp3.internal.b.y(encodedValues);
    }

    @Override // okhttp3.F
    public final long a() {
        return e(null, true);
    }

    @Override // okhttp3.F
    public final w b() {
        return c;
    }

    @Override // okhttp3.F
    public final void d(InterfaceC5092i sink) throws EOFException {
        Intrinsics.checkNotNullParameter(sink, "sink");
        e(sink, false);
    }

    public final long e(InterfaceC5092i interfaceC5092i, boolean z) throws EOFException {
        C5091h c5091hC;
        if (z) {
            c5091hC = new C5091h();
        } else {
            Intrinsics.d(interfaceC5092i);
            c5091hC = interfaceC5092i.c();
        }
        List list = this.a;
        int size = list.size();
        for (int i = 0; i < size; i++) {
            if (i > 0) {
                c5091hC.p0(38);
            }
            c5091hC.u0((String) list.get(i));
            c5091hC.p0(61);
            c5091hC.u0((String) this.b.get(i));
        }
        if (!z) {
            return 0L;
        }
        long j = c5091hC.b;
        c5091hC.d();
        return j;
    }
}

package okhttp3;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3347h2;
import java.io.EOFException;
import java.util.List;
import java.util.regex.Pattern;
import kotlin.jvm.internal.Intrinsics;
import okio.C5091h;
import okio.InterfaceC5092i;

/* loaded from: classes3.dex */
public final class y extends F {
    public static final w e;
    public static final w f;
    public static final byte[] g;
    public static final byte[] h;
    public static final byte[] i;
    public final okio.k a;
    public final List b;
    public final w c;
    public long d;

    static {
        Pattern pattern = w.e;
        e = AbstractC3347h2.c("multipart/mixed");
        AbstractC3347h2.c("multipart/alternative");
        AbstractC3347h2.c("multipart/digest");
        AbstractC3347h2.c("multipart/parallel");
        f = AbstractC3347h2.c("multipart/form-data");
        g = new byte[]{58, 32};
        h = new byte[]{13, 10};
        i = new byte[]{45, 45};
    }

    public y(okio.k boundaryByteString, w type, List parts) {
        Intrinsics.checkNotNullParameter(boundaryByteString, "boundaryByteString");
        Intrinsics.checkNotNullParameter(type, "type");
        Intrinsics.checkNotNullParameter(parts, "parts");
        this.a = boundaryByteString;
        this.b = parts;
        Pattern pattern = w.e;
        this.c = AbstractC3347h2.c(type + "; boundary=" + boundaryByteString.s());
        this.d = -1L;
    }

    @Override // okhttp3.F
    public final long a() throws EOFException {
        long j = this.d;
        if (j != -1) {
            return j;
        }
        long jE = e(null, true);
        this.d = jE;
        return jE;
    }

    @Override // okhttp3.F
    public final w b() {
        return this.c;
    }

    @Override // okhttp3.F
    public final void d(InterfaceC5092i sink) throws EOFException {
        Intrinsics.checkNotNullParameter(sink, "sink");
        e(sink, false);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final long e(InterfaceC5092i interfaceC5092i, boolean z) throws EOFException {
        C5091h c5091h;
        InterfaceC5092i c5091h2;
        if (z) {
            c5091h2 = new C5091h();
            c5091h = c5091h2;
        } else {
            c5091h = 0;
            c5091h2 = interfaceC5092i;
        }
        List list = this.b;
        int size = list.size();
        long j = 0;
        int i2 = 0;
        while (true) {
            okio.k kVar = this.a;
            byte[] bArr = i;
            byte[] bArr2 = h;
            if (i2 >= size) {
                Intrinsics.d(c5091h2);
                c5091h2.X(bArr);
                c5091h2.Z(kVar);
                c5091h2.X(bArr);
                c5091h2.X(bArr2);
                if (!z) {
                    return j;
                }
                Intrinsics.d(c5091h);
                long j2 = j + c5091h.b;
                c5091h.d();
                return j2;
            }
            x xVar = (x) list.get(i2);
            r rVar = xVar.a;
            Intrinsics.d(c5091h2);
            c5091h2.X(bArr);
            c5091h2.Z(kVar);
            c5091h2.X(bArr2);
            int size2 = rVar.size();
            for (int i3 = 0; i3 < size2; i3++) {
                c5091h2.H(rVar.b(i3)).X(g).H(rVar.g(i3)).X(bArr2);
            }
            F f2 = xVar.b;
            w wVarB = f2.b();
            if (wVarB != null) {
                c5091h2.H("Content-Type: ").H(wVarB.a).X(bArr2);
            }
            long jA = f2.a();
            if (jA != -1) {
                c5091h2.H("Content-Length: ").h0(jA).X(bArr2);
            } else if (z) {
                Intrinsics.d(c5091h);
                c5091h.d();
                return -1L;
            }
            c5091h2.X(bArr2);
            if (z) {
                j += jA;
            } else {
                f2.d(c5091h2);
            }
            c5091h2.X(bArr2);
            i2++;
        }
    }
}

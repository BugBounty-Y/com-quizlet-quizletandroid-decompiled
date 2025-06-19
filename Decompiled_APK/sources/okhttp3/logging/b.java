package okhttp3.logging;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3379p2;
import com.google.firebase.components.n;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.B;
import okhttp3.C;
import okhttp3.F;
import okhttp3.H;
import okhttp3.J;
import okhttp3.internal.connection.i;
import okhttp3.internal.http.e;
import okhttp3.internal.http.f;
import okhttp3.r;
import okhttp3.t;
import okhttp3.u;
import okhttp3.w;
import okio.C5091h;
import okio.InterfaceC5093j;
import okio.q;

/* loaded from: classes3.dex */
public final class b implements u {
    public volatile M a;
    public volatile a b;

    public final void a(r rVar, int i) {
        this.a.contains(rVar.b(i));
        n.a(rVar.b(i) + ": " + rVar.g(i));
    }

    @Override // okhttp3.u
    public final H intercept(t chain) throws Exception {
        String string;
        String str;
        boolean z;
        boolean z2;
        J j;
        long j2;
        String string2;
        Long lValueOf;
        Charset UTF_8;
        Charset UTF_82;
        Intrinsics.checkNotNullParameter(chain, "chain");
        a aVar = this.b;
        f fVar = (f) chain;
        C c = fVar.e;
        if (aVar == a.a) {
            return fVar.b(c);
        }
        boolean z3 = true;
        boolean z4 = aVar == a.d;
        if (!z4 && aVar != a.c) {
            z3 = false;
        }
        F f = c.d;
        androidx.compose.material.ripple.r rVar = fVar.d;
        i iVar = rVar != null ? (i) rVar.e : null;
        StringBuilder sb = new StringBuilder("--> ");
        sb.append(c.b);
        sb.append(' ');
        sb.append(c.a);
        if (iVar != null) {
            StringBuilder sb2 = new StringBuilder(" ");
            B b = iVar.f;
            Intrinsics.d(b);
            sb2.append(b);
            string = sb2.toString();
        } else {
            string = "";
        }
        sb.append(string);
        String string3 = sb.toString();
        if (!z3 && f != null) {
            StringBuilder sbX = android.support.v4.media.session.a.x(string3, " (");
            sbX.append(f.a());
            sbX.append("-byte body)");
            string3 = sbX.toString();
        }
        n.a(string3);
        if (z3) {
            r rVar2 = c.c;
            if (f != null) {
                w wVarB = f.b();
                z = z4;
                if (wVarB == null || rVar2.a("Content-Type") != null) {
                    z2 = z3;
                } else {
                    z2 = z3;
                    n.a("Content-Type: " + wVarB);
                }
                if (f.a() != -1 && rVar2.a("Content-Length") == null) {
                    n.a("Content-Length: " + f.a());
                }
            } else {
                z = z4;
                z2 = z3;
            }
            int size = rVar2.size();
            for (int i = 0; i < size; i++) {
                a(rVar2, i);
            }
            if (!z || f == null) {
                str = "identity";
                n.a("--> END " + c.b);
            } else {
                String strA = c.c.a("Content-Encoding");
                if (strA != null && !strA.equalsIgnoreCase("identity") && !strA.equalsIgnoreCase("gzip")) {
                    n.a("--> END " + c.b + " (encoded body omitted)");
                } else if (f instanceof io.ktor.client.engine.okhttp.i) {
                    n.a("--> END " + c.b + " (one-shot body omitted)");
                } else {
                    C5091h c5091h = new C5091h();
                    f.d(c5091h);
                    w wVarB2 = f.b();
                    if (wVarB2 == null || (UTF_82 = wVarB2.a(StandardCharsets.UTF_8)) == null) {
                        UTF_82 = StandardCharsets.UTF_8;
                        Intrinsics.checkNotNullExpressionValue(UTF_82, "UTF_8");
                    }
                    n.a("");
                    if (AbstractC3379p2.d(c5091h)) {
                        n.a(c5091h.K(UTF_82));
                        n.a("--> END " + c.b + " (" + f.a() + "-byte body)");
                        str = "identity";
                    } else {
                        StringBuilder sb3 = new StringBuilder("--> END ");
                        sb3.append(c.b);
                        sb3.append(" (binary ");
                        str = "identity";
                        sb3.append(f.a());
                        sb3.append("-byte body omitted)");
                        n.a(sb3.toString());
                    }
                }
                str = "identity";
            }
        } else {
            str = "identity";
            z = z4;
            z2 = z3;
        }
        long jNanoTime = System.nanoTime();
        try {
            H hB = ((f) chain).b(c);
            long millis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - jNanoTime);
            J j3 = hB.g;
            Intrinsics.d(j3);
            long jA = j3.a();
            if (jA != -1) {
                j = j3;
                StringBuilder sb4 = new StringBuilder();
                sb4.append(jA);
                j2 = jA;
                sb4.append("-byte");
                string2 = sb4.toString();
            } else {
                j = j3;
                j2 = jA;
                string2 = "unknown-length";
            }
            StringBuilder sb5 = new StringBuilder("<-- ");
            sb5.append(hB.d);
            sb5.append(hB.c.length() == 0 ? "" : AbstractC0147y.d(" ", hB.c));
            sb5.append(' ');
            sb5.append(hB.a.a);
            sb5.append(" (");
            sb5.append(millis);
            sb5.append("ms");
            sb5.append(!z2 ? android.support.v4.media.session.a.B(", ", string2, " body") : "");
            sb5.append(')');
            n.a(sb5.toString());
            if (z2) {
                r rVar3 = hB.f;
                int size2 = rVar3.size();
                for (int i2 = 0; i2 < size2; i2++) {
                    a(rVar3, i2);
                }
                if (z && e.a(hB)) {
                    String strA2 = hB.f.a("Content-Encoding");
                    if (strA2 != null && !strA2.equalsIgnoreCase(str) && !strA2.equalsIgnoreCase("gzip")) {
                        n.a("<-- END HTTP (encoded body omitted)");
                        return hB;
                    }
                    InterfaceC5093j interfaceC5093jF0 = j.f0();
                    interfaceC5093jF0.e(Long.MAX_VALUE);
                    C5091h c5091hC = interfaceC5093jF0.c();
                    if ("gzip".equalsIgnoreCase(rVar3.a("Content-Encoding"))) {
                        lValueOf = Long.valueOf(c5091hC.b);
                        q qVar = new q(c5091hC.clone());
                        try {
                            c5091hC = new C5091h();
                            c5091hC.M(qVar);
                            qVar.close();
                        } finally {
                        }
                    } else {
                        lValueOf = null;
                    }
                    w wVarD = j.d();
                    if (wVarD == null || (UTF_8 = wVarD.a(StandardCharsets.UTF_8)) == null) {
                        UTF_8 = StandardCharsets.UTF_8;
                        Intrinsics.checkNotNullExpressionValue(UTF_8, "UTF_8");
                    }
                    if (!AbstractC3379p2.d(c5091hC)) {
                        n.a("");
                        n.a("<-- END HTTP (binary " + c5091hC.b + "-byte body omitted)");
                        return hB;
                    }
                    if (j2 != 0) {
                        n.a("");
                        n.a(c5091hC.clone().K(UTF_8));
                    }
                    if (lValueOf == null) {
                        n.a("<-- END HTTP (" + c5091hC.b + "-byte body)");
                        return hB;
                    }
                    n.a("<-- END HTTP (" + c5091hC.b + "-byte, " + lValueOf + "-gzipped-byte body)");
                    return hB;
                }
                n.a("<-- END HTTP");
            }
            return hB;
        } catch (Exception e) {
            n.a("<-- HTTP FAILED: " + e);
            throw e;
        }
    }
}

package com.google.firebase.crashlytics.internal.model.serialization;

import android.util.JsonReader;
import androidx.webkit.internal.p;
import com.google.android.gms.measurement.internal.Z;
import com.google.firebase.components.n;
import com.google.firebase.crashlytics.internal.model.A0;
import com.google.firebase.crashlytics.internal.model.B;
import com.google.firebase.crashlytics.internal.model.B0;
import com.google.firebase.crashlytics.internal.model.C;
import com.google.firebase.crashlytics.internal.model.C0;
import com.google.firebase.crashlytics.internal.model.C3924a;
import com.google.firebase.crashlytics.internal.model.C3925a0;
import com.google.firebase.crashlytics.internal.model.C3926b;
import com.google.firebase.crashlytics.internal.model.C3928c;
import com.google.firebase.crashlytics.internal.model.C3929c0;
import com.google.firebase.crashlytics.internal.model.C3930d;
import com.google.firebase.crashlytics.internal.model.C3931d0;
import com.google.firebase.crashlytics.internal.model.C3932e;
import com.google.firebase.crashlytics.internal.model.C3934f;
import com.google.firebase.crashlytics.internal.model.C3935f0;
import com.google.firebase.crashlytics.internal.model.C3936g;
import com.google.firebase.crashlytics.internal.model.C3937g0;
import com.google.firebase.crashlytics.internal.model.C3938h;
import com.google.firebase.crashlytics.internal.model.C3939h0;
import com.google.firebase.crashlytics.internal.model.C3940i;
import com.google.firebase.crashlytics.internal.model.C3942j;
import com.google.firebase.crashlytics.internal.model.C3943j0;
import com.google.firebase.crashlytics.internal.model.C3944k;
import com.google.firebase.crashlytics.internal.model.C3945k0;
import com.google.firebase.crashlytics.internal.model.C3946l;
import com.google.firebase.crashlytics.internal.model.C3948m;
import com.google.firebase.crashlytics.internal.model.C3950n;
import com.google.firebase.crashlytics.internal.model.C3952o;
import com.google.firebase.crashlytics.internal.model.C3954p;
import com.google.firebase.crashlytics.internal.model.C3955q;
import com.google.firebase.crashlytics.internal.model.C3956s;
import com.google.firebase.crashlytics.internal.model.C3957t;
import com.google.firebase.crashlytics.internal.model.C3958u;
import com.google.firebase.crashlytics.internal.model.C3959v;
import com.google.firebase.crashlytics.internal.model.C3960w;
import com.google.firebase.crashlytics.internal.model.C3961x;
import com.google.firebase.crashlytics.internal.model.C3962y;
import com.google.firebase.crashlytics.internal.model.C3963z;
import com.google.firebase.crashlytics.internal.model.D;
import com.google.firebase.crashlytics.internal.model.D0;
import com.google.firebase.crashlytics.internal.model.E;
import com.google.firebase.crashlytics.internal.model.E0;
import com.google.firebase.crashlytics.internal.model.F;
import com.google.firebase.crashlytics.internal.model.F0;
import com.google.firebase.crashlytics.internal.model.G;
import com.google.firebase.crashlytics.internal.model.G0;
import com.google.firebase.crashlytics.internal.model.H;
import com.google.firebase.crashlytics.internal.model.H0;
import com.google.firebase.crashlytics.internal.model.I0;
import com.google.firebase.crashlytics.internal.model.J;
import com.google.firebase.crashlytics.internal.model.J0;
import com.google.firebase.crashlytics.internal.model.K;
import com.google.firebase.crashlytics.internal.model.K0;
import com.google.firebase.crashlytics.internal.model.L;
import com.google.firebase.crashlytics.internal.model.L0;
import com.google.firebase.crashlytics.internal.model.M0;
import com.google.firebase.crashlytics.internal.model.N;
import com.google.firebase.crashlytics.internal.model.N0;
import com.google.firebase.crashlytics.internal.model.O0;
import com.google.firebase.crashlytics.internal.model.P;
import com.google.firebase.crashlytics.internal.model.Q;
import com.google.firebase.crashlytics.internal.model.S;
import com.google.firebase.crashlytics.internal.model.T;
import com.google.firebase.crashlytics.internal.model.U;
import com.google.firebase.crashlytics.internal.model.V;
import com.google.firebase.crashlytics.internal.model.W;
import com.google.firebase.crashlytics.internal.model.X;
import com.google.firebase.crashlytics.internal.model.Y;
import com.google.firebase.crashlytics.internal.model.p0;
import com.google.firebase.crashlytics.internal.model.q0;
import com.google.firebase.crashlytics.internal.model.r;
import com.google.firebase.crashlytics.internal.model.r0;
import com.google.firebase.crashlytics.internal.model.s0;
import com.google.firebase.crashlytics.internal.model.t0;
import com.google.firebase.crashlytics.internal.model.u0;
import com.google.firebase.crashlytics.internal.model.v0;
import com.google.firebase.crashlytics.internal.model.w0;
import com.google.firebase.crashlytics.internal.model.x0;
import com.google.firebase.crashlytics.internal.model.y0;
import com.google.firebase.crashlytics.internal.model.z0;
import com.google.firebase.encoders.json.d;
import java.io.IOException;
import java.io.StringReader;
import java.util.List;

/* loaded from: classes2.dex */
public final class a {
    public static final p a;

    static {
        d dVar = new d();
        C3930d c3930d = C3930d.a;
        dVar.g(O0.class, c3930d);
        dVar.g(B.class, c3930d);
        C3942j c3942j = C3942j.a;
        dVar.g(N0.class, c3942j);
        dVar.g(J.class, c3942j);
        C3936g c3936g = C3936g.a;
        dVar.g(v0.class, c3936g);
        dVar.g(K.class, c3936g);
        C3938h c3938h = C3938h.a;
        dVar.g(u0.class, c3938h);
        dVar.g(L.class, c3938h);
        C3963z c3963z = C3963z.a;
        dVar.g(M0.class, c3963z);
        dVar.g(C3945k0.class, c3963z);
        C3962y c3962y = C3962y.a;
        dVar.g(L0.class, c3962y);
        dVar.g(C3943j0.class, c3962y);
        C3940i c3940i = C3940i.a;
        dVar.g(w0.class, c3940i);
        dVar.g(N.class, c3940i);
        C3957t c3957t = C3957t.a;
        dVar.g(K0.class, c3957t);
        dVar.g(P.class, c3957t);
        C3944k c3944k = C3944k.a;
        dVar.g(E0.class, c3944k);
        dVar.g(Q.class, c3944k);
        C3948m c3948m = C3948m.a;
        dVar.g(C0.class, c3948m);
        dVar.g(S.class, c3948m);
        C3954p c3954p = C3954p.a;
        dVar.g(B0.class, c3954p);
        dVar.g(W.class, c3954p);
        C3955q c3955q = C3955q.a;
        dVar.g(A0.class, c3955q);
        dVar.g(Y.class, c3955q);
        C3950n c3950n = C3950n.a;
        dVar.g(y0.class, c3950n);
        dVar.g(U.class, c3950n);
        C3926b c3926b = C3926b.a;
        dVar.g(q0.class, c3926b);
        dVar.g(D.class, c3926b);
        C3924a c3924a = C3924a.a;
        dVar.g(p0.class, c3924a);
        dVar.g(E.class, c3924a);
        C3952o c3952o = C3952o.a;
        dVar.g(z0.class, c3952o);
        dVar.g(V.class, c3952o);
        C3946l c3946l = C3946l.a;
        dVar.g(x0.class, c3946l);
        dVar.g(T.class, c3946l);
        C3928c c3928c = C3928c.a;
        dVar.g(r0.class, c3928c);
        dVar.g(F.class, c3928c);
        r rVar = r.a;
        dVar.g(D0.class, rVar);
        dVar.g(C3925a0.class, rVar);
        C3956s c3956s = C3956s.a;
        dVar.g(F0.class, c3956s);
        dVar.g(C3929c0.class, c3956s);
        C3958u c3958u = C3958u.a;
        dVar.g(G0.class, c3958u);
        dVar.g(C3931d0.class, c3958u);
        C3961x c3961x = C3961x.a;
        dVar.g(J0.class, c3961x);
        dVar.g(C3939h0.class, c3961x);
        C3959v c3959v = C3959v.a;
        dVar.g(I0.class, c3959v);
        dVar.g(C3935f0.class, c3959v);
        C3960w c3960w = C3960w.a;
        dVar.g(H0.class, c3960w);
        dVar.g(C3937g0.class, c3960w);
        C3932e c3932e = C3932e.a;
        dVar.g(t0.class, c3932e);
        dVar.g(G.class, c3932e);
        C3934f c3934f = C3934f.a;
        dVar.g(s0.class, c3934f);
        dVar.g(H.class, c3934f);
        dVar.d = true;
        a = new p(dVar, 25);
    }

    public static Y a(JsonReader jsonReader) throws IOException {
        X x = new X();
        jsonReader.beginObject();
        while (jsonReader.hasNext()) {
            String strNextName = jsonReader.nextName();
            strNextName.getClass();
            switch (strNextName) {
                case "offset":
                    x.d = jsonReader.nextLong();
                    x.f = (byte) (x.f | 2);
                    break;
                case "symbol":
                    String strNextString = jsonReader.nextString();
                    if (strNextString == null) {
                        throw new NullPointerException("Null symbol");
                    }
                    x.b = strNextString;
                    break;
                case "pc":
                    x.a = jsonReader.nextLong();
                    x.f = (byte) (x.f | 1);
                    break;
                case "file":
                    x.c = jsonReader.nextString();
                    break;
                case "importance":
                    x.e = jsonReader.nextInt();
                    x.f = (byte) (x.f | 4);
                    break;
                default:
                    jsonReader.skipValue();
                    break;
            }
        }
        jsonReader.endObject();
        return x.a();
    }

    public static F b(JsonReader jsonReader) throws IOException {
        jsonReader.beginObject();
        String strNextString = null;
        String strNextString2 = null;
        while (jsonReader.hasNext()) {
            String strNextName = jsonReader.nextName();
            strNextName.getClass();
            if (strNextName.equals("key")) {
                strNextString = jsonReader.nextString();
                if (strNextString == null) {
                    throw new NullPointerException("Null key");
                }
            } else if (strNextName.equals("value")) {
                strNextString2 = jsonReader.nextString();
                if (strNextString2 == null) {
                    throw new NullPointerException("Null value");
                }
            } else {
                jsonReader.skipValue();
            }
        }
        jsonReader.endObject();
        if (strNextString != null && strNextString2 != null) {
            return new F(strNextString, strNextString2);
        }
        StringBuilder sb = new StringBuilder();
        if (strNextString == null) {
            sb.append(" key");
        }
        if (strNextString2 == null) {
            sb.append(" value");
        }
        throw new IllegalStateException(Z.i("Missing required properties:", sb));
    }

    public static D c(JsonReader jsonReader) throws IOException {
        C c = new C();
        jsonReader.beginObject();
        while (jsonReader.hasNext()) {
            String strNextName = jsonReader.nextName();
            strNextName.getClass();
            switch (strNextName) {
                case "buildIdMappingForArch":
                    c.i = d(jsonReader, new n(6));
                    break;
                case "pid":
                    c.a = jsonReader.nextInt();
                    c.j = (byte) (c.j | 1);
                    break;
                case "pss":
                    c.e = jsonReader.nextLong();
                    c.j = (byte) (c.j | 8);
                    break;
                case "rss":
                    c.f = jsonReader.nextLong();
                    c.j = (byte) (c.j | 16);
                    break;
                case "timestamp":
                    c.g = jsonReader.nextLong();
                    c.j = (byte) (c.j | 32);
                    break;
                case "processName":
                    String strNextString = jsonReader.nextString();
                    if (strNextString == null) {
                        throw new NullPointerException("Null processName");
                    }
                    c.b = strNextString;
                    break;
                case "reasonCode":
                    c.c = jsonReader.nextInt();
                    c.j = (byte) (c.j | 2);
                    break;
                case "traceFile":
                    c.h = jsonReader.nextString();
                    break;
                case "importance":
                    c.d = jsonReader.nextInt();
                    c.j = (byte) (c.j | 4);
                    break;
                default:
                    jsonReader.skipValue();
                    break;
            }
        }
        jsonReader.endObject();
        return c.a();
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:108:0x01ae  */
    /* JADX WARN: Removed duplicated region for block: B:13:0x004b  */
    /* JADX WARN: Removed duplicated region for block: B:204:0x0320  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x0101  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.util.List d(android.util.JsonReader r21, com.google.firebase.components.n r22) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 1076
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.crashlytics.internal.model.serialization.a.d(android.util.JsonReader, com.google.firebase.components.n):java.util.List");
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:111:0x01b2  */
    /* JADX WARN: Removed duplicated region for block: B:146:0x0230  */
    /* JADX WARN: Removed duplicated region for block: B:241:0x03d6  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x00f1  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0022  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.google.firebase.crashlytics.internal.model.P e(android.util.JsonReader r29) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 1352
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.crashlytics.internal.model.serialization.a.e(android.util.JsonReader):com.google.firebase.crashlytics.internal.model.P");
    }

    public static U f(JsonReader jsonReader) throws IOException {
        jsonReader.beginObject();
        int iNextInt = 0;
        String str = null;
        String strNextString = null;
        List list = null;
        U uF = null;
        byte b = 0;
        while (jsonReader.hasNext()) {
            String strNextName = jsonReader.nextName();
            strNextName.getClass();
            switch (strNextName) {
                case "frames":
                    List listD = d(jsonReader, new n(11));
                    if (listD == null) {
                        throw new NullPointerException("Null frames");
                    }
                    list = listD;
                    break;
                case "reason":
                    strNextString = jsonReader.nextString();
                    break;
                case "type":
                    String strNextString2 = jsonReader.nextString();
                    if (strNextString2 == null) {
                        throw new NullPointerException("Null type");
                    }
                    str = strNextString2;
                    break;
                case "causedBy":
                    uF = f(jsonReader);
                    break;
                case "overflowCount":
                    iNextInt = jsonReader.nextInt();
                    b = (byte) (b | 1);
                    break;
                default:
                    jsonReader.skipValue();
                    break;
            }
        }
        jsonReader.endObject();
        if (b == 1 && str != null && list != null) {
            return new U(str, strNextString, list, uF, iNextInt);
        }
        StringBuilder sb = new StringBuilder();
        if (str == null) {
            sb.append(" type");
        }
        if (list == null) {
            sb.append(" frames");
        }
        if ((b & 1) == 0) {
            sb.append(" overflowCount");
        }
        throw new IllegalStateException(Z.i("Missing required properties:", sb));
    }

    public static C3925a0 g(JsonReader jsonReader) throws IOException {
        com.google.firebase.crashlytics.internal.model.Z z = new com.google.firebase.crashlytics.internal.model.Z();
        jsonReader.beginObject();
        while (jsonReader.hasNext()) {
            String strNextName = jsonReader.nextName();
            strNextName.getClass();
            switch (strNextName) {
                case "pid":
                    z.b = jsonReader.nextInt();
                    z.e = (byte) (z.e | 1);
                    break;
                case "processName":
                    String strNextString = jsonReader.nextString();
                    if (strNextString == null) {
                        throw new NullPointerException("Null processName");
                    }
                    z.a = strNextString;
                    break;
                case "defaultProcess":
                    z.d = jsonReader.nextBoolean();
                    z.e = (byte) (z.e | 4);
                    break;
                case "importance":
                    z.c = jsonReader.nextInt();
                    z.e = (byte) (z.e | 2);
                    break;
                default:
                    jsonReader.skipValue();
                    break;
            }
        }
        jsonReader.endObject();
        return z.a();
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:143:0x021a  */
    /* JADX WARN: Removed duplicated region for block: B:201:0x02dc  */
    /* JADX WARN: Removed duplicated region for block: B:243:0x038d  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x00f6  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0039  */
    /* JADX WARN: Type inference failed for: r10v10 */
    /* JADX WARN: Type inference failed for: r10v12 */
    /* JADX WARN: Type inference failed for: r10v14 */
    /* JADX WARN: Type inference failed for: r10v16 */
    /* JADX WARN: Type inference failed for: r10v18 */
    /* JADX WARN: Type inference failed for: r10v2 */
    /* JADX WARN: Type inference failed for: r10v20 */
    /* JADX WARN: Type inference failed for: r10v22 */
    /* JADX WARN: Type inference failed for: r10v24 */
    /* JADX WARN: Type inference failed for: r10v25 */
    /* JADX WARN: Type inference failed for: r10v32 */
    /* JADX WARN: Type inference failed for: r10v4 */
    /* JADX WARN: Type inference failed for: r10v6 */
    /* JADX WARN: Type inference failed for: r10v8 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.google.firebase.crashlytics.internal.model.B h(android.util.JsonReader r32) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 1790
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.crashlytics.internal.model.serialization.a.h(android.util.JsonReader):com.google.firebase.crashlytics.internal.model.B");
    }

    public static B i(String str) {
        try {
            JsonReader jsonReader = new JsonReader(new StringReader(str));
            try {
                B bH = h(jsonReader);
                jsonReader.close();
                return bH;
            } finally {
            }
        } catch (IllegalStateException e) {
            throw new IOException(e);
        }
    }
}

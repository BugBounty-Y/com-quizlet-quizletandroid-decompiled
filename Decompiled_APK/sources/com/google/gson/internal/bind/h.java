package com.google.gson.internal.bind;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.comscore.streaming.ContentType;
import com.google.gson.q;
import java.io.IOException;
import java.io.Serializable;
import java.util.Arrays;
import java.util.Iterator;

/* loaded from: classes2.dex */
public final class h extends q {
    public static final g b = new g(new h(0), 0);
    public static final a c = new a(2);
    public final /* synthetic */ int a;

    public /* synthetic */ h(int i) {
        this.a = i;
    }

    public static com.google.gson.m b(com.google.gson.stream.a aVar) {
        int iK = AbstractC0147y.k(aVar.l0());
        if (iK == 0) {
            com.google.gson.l lVar = new com.google.gson.l();
            aVar.a();
            while (aVar.q()) {
                lVar.a.add(b(aVar));
            }
            aVar.j();
            return lVar;
        }
        if (iK == 2) {
            com.google.gson.o oVar = new com.google.gson.o();
            aVar.d();
            while (aVar.q()) {
                oVar.a.put(aVar.Q(), b(aVar));
            }
            aVar.l();
            return oVar;
        }
        if (iK == 5) {
            return new com.google.gson.p(aVar.d0());
        }
        if (iK == 6) {
            return new com.google.gson.p(new com.google.gson.internal.h(aVar.d0()));
        }
        if (iK == 7) {
            return new com.google.gson.p(Boolean.valueOf(aVar.B()));
        }
        if (iK != 8) {
            throw new IllegalArgumentException();
        }
        aVar.a0();
        return com.google.gson.n.a;
    }

    public static void c(com.google.gson.stream.b bVar, com.google.gson.m mVar) throws IOException {
        if (mVar == null || (mVar instanceof com.google.gson.n)) {
            bVar.f();
            return;
        }
        boolean z = mVar instanceof com.google.gson.p;
        if (z) {
            if (!z) {
                throw new IllegalStateException("Not a JSON Primitive: " + mVar);
            }
            com.google.gson.p pVar = (com.google.gson.p) mVar;
            Serializable serializable = pVar.a;
            if (!(serializable instanceof Number)) {
                if (serializable instanceof Boolean) {
                    boolean zBooleanValue = serializable instanceof Boolean ? ((Boolean) serializable).booleanValue() : Boolean.parseBoolean(pVar.b());
                    bVar.l();
                    bVar.a();
                    bVar.a.write(zBooleanValue ? "true" : "false");
                    return;
                }
                String strB = pVar.b();
                if (strB == null) {
                    bVar.f();
                    return;
                }
                bVar.l();
                bVar.a();
                bVar.j(strB);
                return;
            }
            Number numberC = pVar.c();
            if (numberC == null) {
                bVar.f();
                return;
            }
            bVar.l();
            String string = numberC.toString();
            if (bVar.e || !(string.equals("-Infinity") || string.equals("Infinity") || string.equals("NaN"))) {
                bVar.a();
                bVar.a.append((CharSequence) string);
                return;
            } else {
                throw new IllegalArgumentException("Numeric values must be finite, but was " + numberC);
            }
        }
        boolean z2 = mVar instanceof com.google.gson.l;
        if (z2) {
            bVar.l();
            bVar.a();
            int i = bVar.c;
            int[] iArr = bVar.b;
            if (i == iArr.length) {
                bVar.b = Arrays.copyOf(iArr, i * 2);
            }
            int[] iArr2 = bVar.b;
            int i2 = bVar.c;
            bVar.c = i2 + 1;
            iArr2[i2] = 1;
            bVar.a.write(91);
            if (!z2) {
                throw new IllegalStateException("Not a JSON Array: " + mVar);
            }
            Iterator it2 = ((com.google.gson.l) mVar).a.iterator();
            while (it2.hasNext()) {
                c(bVar, (com.google.gson.m) it2.next());
            }
            bVar.d(1, ']', 2);
            return;
        }
        boolean z3 = mVar instanceof com.google.gson.o;
        if (!z3) {
            throw new IllegalArgumentException("Couldn't write " + mVar.getClass());
        }
        bVar.l();
        bVar.a();
        int i3 = bVar.c;
        int[] iArr3 = bVar.b;
        if (i3 == iArr3.length) {
            bVar.b = Arrays.copyOf(iArr3, i3 * 2);
        }
        int[] iArr4 = bVar.b;
        int i4 = bVar.c;
        bVar.c = i4 + 1;
        iArr4[i4] = 3;
        bVar.a.write(ContentType.USER_GENERATED_LIVE);
        if (!z3) {
            throw new IllegalStateException("Not a JSON Object: " + mVar);
        }
        Iterator it3 = ((com.google.gson.internal.j) ((com.google.gson.o) mVar).a.entrySet()).iterator();
        while (((com.google.gson.internal.k) it3).hasNext()) {
            com.google.gson.internal.l lVarA = ((com.google.gson.internal.i) it3).a();
            String str = (String) lVarA.getKey();
            if (str == null) {
                throw new NullPointerException("name == null");
            }
            if (bVar.f != null) {
                throw new IllegalStateException();
            }
            if (bVar.c == 0) {
                throw new IllegalStateException("JsonWriter is closed.");
            }
            bVar.f = str;
            c(bVar, (com.google.gson.m) lVarA.getValue());
        }
        bVar.d(3, '}', 5);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:63:0x00f4  */
    /* JADX WARN: Type inference failed for: r0v12, types: [com.google.gson.internal.m] */
    @Override // com.google.gson.q
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(com.google.gson.stream.a r10) {
        /*
            Method dump skipped, instructions count: 1174
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.gson.internal.bind.h.a(com.google.gson.stream.a):java.lang.Object");
    }

    public h(com.google.gson.k kVar) {
        this.a = 1;
    }
}

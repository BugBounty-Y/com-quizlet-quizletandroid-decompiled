package com.squareup.moshi;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/* loaded from: classes3.dex */
public final class G extends l {
    public final /* synthetic */ int a = 0;
    public final Object b;
    public final Object c;
    public final Object d;
    public final Object e;
    public final Object f;
    public final Object g;

    public G(D d) {
        this.b = d;
        d.getClass();
        Set set = com.squareup.moshi.internal.b.a;
        this.c = d.a(List.class, set, null);
        this.d = d.a(Map.class, set, null);
        this.e = d.a(String.class, set, null);
        this.f = d.a(Double.class, set, null);
        this.g = d.a(Boolean.class, set, null);
    }

    @Override // com.squareup.moshi.l
    public final Object a(p pVar) throws IOException {
        switch (this.a) {
            case 0:
                int iOrdinal = pVar.Q().ordinal();
                if (iOrdinal == 0) {
                    return ((l) this.c).a(pVar);
                }
                if (iOrdinal == 2) {
                    return ((l) this.d).a(pVar);
                }
                if (iOrdinal == 5) {
                    return ((l) this.e).a(pVar);
                }
                if (iOrdinal == 6) {
                    return ((l) this.f).a(pVar);
                }
                if (iOrdinal == 7) {
                    return ((l) this.g).a(pVar);
                }
                if (iOrdinal == 8) {
                    pVar.C();
                    return null;
                }
                throw new IllegalStateException("Expected a value but was " + pVar.Q() + " at path " + pVar.j());
            default:
                p pVarY = pVar.Y();
                pVarY.f = false;
                try {
                    int iH = h(pVarY);
                    pVarY.close();
                    if (iH != -1) {
                        return ((l) ((ArrayList) this.e).get(iH)).a(pVar);
                    }
                    throw null;
                } catch (Throwable th) {
                    pVarY.close();
                    throw th;
                }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:29:0x00a3 A[PHI: r1
  0x00a3: PHI (r1v4 java.lang.Class<?>) = (r1v1 java.lang.Class<?>), (r1v2 java.lang.Class<?>) binds: [B:28:0x00a1, B:31:0x00ab] A[DONT_GENERATE, DONT_INLINE]] */
    @Override // com.squareup.moshi.l
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void g(com.squareup.moshi.w r5, java.lang.Object r6) {
        /*
            r4 = this;
            int r0 = r4.a
            switch(r0) {
                case 0: goto L8c;
                default: goto L5;
            }
        L5:
            java.lang.Class r0 = r6.getClass()
            java.lang.Object r1 = r4.d
            java.util.List r1 = (java.util.List) r1
            int r0 = r1.indexOf(r0)
            r2 = -1
            if (r0 == r2) goto L5f
            java.lang.Object r1 = r4.e
            java.util.ArrayList r1 = (java.util.ArrayList) r1
            java.lang.Object r1 = r1.get(r0)
            com.squareup.moshi.l r1 = (com.squareup.moshi.l) r1
            r5.d()
            if (r1 == 0) goto L37
            java.lang.Object r2 = r4.b
            java.lang.String r2 = (java.lang.String) r2
            r5.l(r2)
            java.lang.Object r2 = r4.c
            java.util.List r2 = (java.util.List) r2
            java.lang.Object r0 = r2.get(r0)
            java.lang.String r0 = (java.lang.String) r0
            r5.C(r0)
        L37:
            int r0 = r5.q()
            r2 = 5
            if (r0 == r2) goto L50
            r2 = 3
            if (r0 == r2) goto L50
            r2 = 2
            if (r0 == r2) goto L50
            r2 = 1
            if (r0 != r2) goto L48
            goto L50
        L48:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "Nesting problem."
            r5.<init>(r6)
            throw r5
        L50:
            int r0 = r5.g
            int r2 = r5.a
            r5.g = r2
            r1.g(r5, r6)
            r5.g = r0
            r5.f()
            return
        L5f:
            java.lang.IllegalArgumentException r5 = new java.lang.IllegalArgumentException
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            java.lang.String r2 = "Expected one of "
            r0.<init>(r2)
            r0.append(r1)
            java.lang.String r1 = " but found "
            r0.append(r1)
            r0.append(r6)
            java.lang.String r1 = ", a "
            r0.append(r1)
            java.lang.Class r6 = r6.getClass()
            r0.append(r6)
            java.lang.String r6 = ". Register this subtype."
            r0.append(r6)
            java.lang.String r6 = r0.toString()
            r5.<init>(r6)
            throw r5
        L8c:
            java.lang.Class r0 = r6.getClass()
            java.lang.Class<java.lang.Object> r1 = java.lang.Object.class
            if (r0 != r1) goto L9b
            r5.d()
            r5.f()
            goto Lbc
        L9b:
            java.lang.Class<java.util.Map> r1 = java.util.Map.class
            boolean r2 = r1.isAssignableFrom(r0)
            if (r2 == 0) goto La5
        La3:
            r0 = r1
            goto Lae
        La5:
            java.lang.Class<java.util.Collection> r1 = java.util.Collection.class
            boolean r2 = r1.isAssignableFrom(r0)
            if (r2 == 0) goto Lae
            goto La3
        Lae:
            java.util.Set r1 = com.squareup.moshi.internal.b.a
            r2 = 0
            java.lang.Object r3 = r4.b
            com.squareup.moshi.D r3 = (com.squareup.moshi.D) r3
            com.squareup.moshi.l r0 = r3.a(r0, r1, r2)
            r0.g(r5, r6)
        Lbc:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.squareup.moshi.G.g(com.squareup.moshi.w, java.lang.Object):void");
    }

    public int h(p pVar) {
        pVar.d();
        while (true) {
            boolean zL = pVar.l();
            String str = (String) this.b;
            if (!zL) {
                throw new JsonDataException("Missing label for ".concat(str));
            }
            if (pVar.k0((com.airbnb.lottie.parser.moshi.c) this.f) != -1) {
                int iL0 = pVar.l0((com.airbnb.lottie.parser.moshi.c) this.g);
                if (iL0 != -1) {
                    return iL0;
                }
                throw new JsonDataException("Expected one of " + ((List) this.c) + " for key '" + str + "' but found '" + pVar.P() + "'. Register a subtype for this label.");
            }
            pVar.m0();
            pVar.n0();
        }
    }

    public final String toString() {
        switch (this.a) {
            case 0:
                return "JsonAdapter(Object)";
            default:
                return android.support.v4.media.session.a.t(new StringBuilder("PolymorphicJsonAdapter("), (String) this.b, ")");
        }
    }

    public G(String str, List list, List list2, ArrayList arrayList) {
        this.b = str;
        this.c = list;
        this.d = list2;
        this.e = arrayList;
        this.f = com.airbnb.lottie.parser.moshi.c.b(str);
        this.g = com.airbnb.lottie.parser.moshi.c.b((String[]) list.toArray(new String[0]));
    }
}

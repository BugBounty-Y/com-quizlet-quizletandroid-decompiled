package org.jsoup.parser;

import java.util.ArrayList;

/* renamed from: org.jsoup.parser.x, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5139x extends B {
    public C5139x() {
        super("InBody", 6);
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Can't wrap try/catch for region: R(11:152|(7:155|(1:157)|158|(1:160)(1:(9:849|163|(2:189|(3:191|(1:193)|194)(3:195|(1:197)|198))|199|834|200|203|(2:205|842)(2:206|841)|207)(9:164|(1:166)(1:167)|168|(1:170)(1:171)|172|(4:174|(2:175|(2:177|(1:851)(1:180))(2:850|181))|179|182)|183|(1:185)|186))|161|187|153)|848|163|(0)|199|834|200|203|(0)(0)|207) */
    /* JADX WARN: Code restructure failed: missing block: B:202:0x0321, code lost:
    
        r35.r.add(r1);
     */
    /* JADX WARN: Removed duplicated region for block: B:152:0x0231  */
    /* JADX WARN: Removed duplicated region for block: B:189:0x02d3  */
    /* JADX WARN: Removed duplicated region for block: B:205:0x0332  */
    /* JADX WARN: Removed duplicated region for block: B:206:0x0334  */
    /* JADX WARN: Removed duplicated region for block: B:316:0x04fa  */
    /* JADX WARN: Removed duplicated region for block: B:836:0x0228 A[SYNTHETIC] */
    @Override // org.jsoup.parser.B
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean c(androidx.sqlite.db.b r34, org.jsoup.parser.C5096b r35) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 3950
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: org.jsoup.parser.C5139x.c(androidx.sqlite.db.b, org.jsoup.parser.b):boolean");
    }

    public final boolean d(androidx.sqlite.db.b bVar, C5096b c5096b) {
        bVar.getClass();
        String str = ((K) bVar).d;
        ArrayList arrayList = c5096b.e;
        if (c5096b.s(str) == null) {
            c5096b.o(this);
            return false;
        }
        for (int size = arrayList.size() - 1; size >= 0; size--) {
            org.jsoup.nodes.i iVar = (org.jsoup.nodes.i) arrayList.get(size);
            if (iVar.d.b.equals(str)) {
                c5096b.p(str);
                if (!c5096b.b(str)) {
                    c5096b.o(this);
                }
                c5096b.I(str);
                return true;
            }
            if (org.jsoup.internal.a.c(iVar.d.b, C5096b.G)) {
                c5096b.o(this);
                return false;
            }
        }
        return true;
    }
}

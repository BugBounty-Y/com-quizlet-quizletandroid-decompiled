package org.jsoup.parser;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3390s2;
import com.j256.ormlite.stmt.query.SimpleComparison;
import java.io.StringReader;
import org.jsoup.helper.ValidationException;

/* loaded from: classes3.dex */
public final class g1 extends f1 {
    @Override // org.jsoup.parser.f1
    public final D c() {
        return D.d;
    }

    @Override // org.jsoup.parser.f1
    public final void d(StringReader stringReader, String str, com.quizlet.data.repository.course.membership.c cVar) {
        super.d(stringReader, str, cVar);
        this.e.add(this.d);
        org.jsoup.nodes.f fVar = this.d.j;
        fVar.h = 2;
        fVar.a = org.jsoup.nodes.j.xhtml;
        fVar.e = false;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v16, types: [org.jsoup.nodes.d, org.jsoup.nodes.m] */
    /* JADX WARN: Type inference failed for: r0v17, types: [org.jsoup.nodes.n] */
    /* JADX WARN: Type inference failed for: r0v18 */
    /* JADX WARN: Type inference failed for: r9v19, types: [org.jsoup.nodes.i] */
    @Override // org.jsoup.parser.f1
    public final boolean e(androidx.sqlite.db.b bVar) {
        String str;
        int iK = AbstractC0147y.k(bVar.b);
        if (iK == 0) {
            I i = (I) bVar;
            org.jsoup.nodes.h hVar = new org.jsoup.nodes.h(this.h.b(i.c.toString()), i.e.toString(), i.f.toString());
            String str2 = i.d;
            if (str2 != null) {
                hVar.B("pubSysKey", str2);
            }
            a().B(hVar);
            return true;
        }
        org.jsoup.nodes.n nVar = null;
        if (iK == 1) {
            L l = (L) bVar;
            E eI = i(l.A(), this.h);
            if (l.z()) {
                l.m.h(this.h);
            }
            D d = this.h;
            org.jsoup.nodes.b bVar2 = l.m;
            d.a(bVar2);
            org.jsoup.nodes.i iVar = new org.jsoup.nodes.i(eI, null, bVar2);
            a().B(iVar);
            if (!l.l) {
                this.e.add(iVar);
                return true;
            }
            if (!E.j.containsKey(eI.a)) {
                eI.f = true;
            }
        } else if (iK == 2) {
            String strB = this.h.b(((K) bVar).c);
            int size = this.e.size();
            int i2 = size + (-1) >= 256 ? size - 257 : 0;
            int size2 = this.e.size() - 1;
            while (true) {
                if (size2 < i2) {
                    break;
                }
                org.jsoup.nodes.n nVar2 = (org.jsoup.nodes.i) this.e.get(size2);
                if (nVar2.r().equals(strB)) {
                    nVar = nVar2;
                    break;
                }
                size2--;
            }
            if (nVar != null) {
                for (int size3 = this.e.size() - 1; size3 >= 0; size3--) {
                    org.jsoup.nodes.n nVar3 = (org.jsoup.nodes.i) this.e.get(size3);
                    this.e.remove(size3);
                    if (nVar3 == nVar) {
                        break;
                    }
                }
            }
        } else {
            if (iK == 3) {
                H h = (H) bVar;
                String string = h.d;
                if (string == null) {
                    string = h.c.toString();
                }
                ?? dVar = new org.jsoup.nodes.d(string);
                if (h.e) {
                    String strD = dVar.D();
                    if (strD.length() > 1 && (strD.startsWith("!") || strD.startsWith("?"))) {
                        String strD2 = dVar.D();
                        String strSubstring = strD2.substring(1, strD2.length() - 1);
                        if (strSubstring.length() <= 1 || (!strSubstring.startsWith("!") && !strSubstring.startsWith("?"))) {
                            String strB2 = android.support.v4.media.session.a.B(SimpleComparison.LESS_THAN_OPERATION, strSubstring, SimpleComparison.GREATER_THAN_OPERATION);
                            com.quizlet.data.repository.course.membership.c cVar = new com.quizlet.data.repository.course.membership.c(new C5096b());
                            cVar.c = D.d;
                            org.jsoup.nodes.g gVarN = cVar.n(strB2, dVar.f());
                            if (gVarN.V().G().size() > 0) {
                                org.jsoup.nodes.i iVar2 = (org.jsoup.nodes.i) gVarN.V().F().get(0);
                                org.jsoup.nodes.n qVar = new org.jsoup.nodes.q(((D) AbstractC3390s2.c(gVarN).c).b(iVar2.d.a), strD2.startsWith("!"));
                                qVar.e().b(iVar2.e());
                                nVar = qVar;
                            }
                        }
                        if (nVar != null) {
                            dVar = nVar;
                        }
                    }
                }
                a().B(dVar);
                return true;
            }
            if (iK == 4) {
                G g = (G) bVar;
                String str3 = g.c;
                a().B(g instanceof F ? new org.jsoup.nodes.c(str3) : new org.jsoup.nodes.p(str3));
                return true;
            }
            if (iK != 5) {
                switch (bVar.b) {
                    case 1:
                        str = "Doctype";
                        break;
                    case 2:
                        str = "StartTag";
                        break;
                    case 3:
                        str = "EndTag";
                        break;
                    case 4:
                        str = "Comment";
                        break;
                    case 5:
                        str = "Character";
                        break;
                    case 6:
                        str = "EOF";
                        break;
                    default:
                        str = "null";
                        break;
                }
                throw new ValidationException("Unexpected token type: ".concat(str));
            }
        }
        return true;
    }
}

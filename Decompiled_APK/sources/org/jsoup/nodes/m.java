package org.jsoup.nodes;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3386r2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3390s2;
import java.util.List;
import org.jsoup.parser.D;

/* loaded from: classes3.dex */
public abstract class m extends n {
    public Object d;

    public final m B(String str, String str2) {
        if (!(this.d instanceof b) && str.equals("#doctype")) {
            this.d = str2;
            return this;
        }
        E();
        D d = (D) AbstractC3390s2.c(this).c;
        d.getClass();
        String strTrim = str.trim();
        if (!d.b) {
            strTrim = AbstractC3386r2.c(strTrim);
        }
        b bVarE = e();
        int iO = bVarE.o(strTrim);
        if (iO == -1) {
            bVarE.c(strTrim, str2);
            return this;
        }
        bVarE.c[iO] = str2;
        if (!bVarE.b[iO].equals(strTrim)) {
            bVarE.b[iO] = strTrim;
        }
        return this;
    }

    public final String D() {
        return d(r());
    }

    public final void E() {
        Object obj = this.d;
        if (obj instanceof b) {
            return;
        }
        b bVar = new b();
        this.d = bVar;
        if (obj != null) {
            bVar.s(r(), (String) obj);
        }
    }

    @Override // org.jsoup.nodes.n
    public final String b(String str) {
        E();
        return super.b(str);
    }

    @Override // org.jsoup.nodes.n
    public final String d(String str) {
        return !(this.d instanceof b) ? r().equals(str) ? (String) this.d : "" : super.d(str);
    }

    @Override // org.jsoup.nodes.n
    public final b e() {
        E();
        return (b) this.d;
    }

    @Override // org.jsoup.nodes.n
    public final String f() {
        n nVar = this.a;
        return nVar != null ? nVar.f() : "";
    }

    @Override // org.jsoup.nodes.n
    public final int g() {
        return 0;
    }

    @Override // org.jsoup.nodes.n
    public final n k(n nVar) {
        m mVar = (m) super.k(nVar);
        Object obj = this.d;
        if (obj instanceof b) {
            mVar.d = ((b) obj).clone();
        }
        return mVar;
    }

    @Override // org.jsoup.nodes.n
    public final n l() {
        return this;
    }

    @Override // org.jsoup.nodes.n
    public final List m() {
        return n.c;
    }

    @Override // org.jsoup.nodes.n
    public final boolean o() {
        return this.d instanceof b;
    }
}

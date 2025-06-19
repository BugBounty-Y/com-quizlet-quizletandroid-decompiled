package androidx.constraintlayout.core.widgets.analyzer;

import com.j256.ormlite.stmt.query.SimpleComparison;
import java.util.ArrayList;
import java.util.Iterator;

/* loaded from: classes.dex */
public class g implements e {
    public final p d;
    public int f;
    public int g;
    public p a = null;
    public boolean b = false;
    public boolean c = false;
    public int e = 1;
    public int h = 1;
    public h i = null;
    public boolean j = false;
    public final ArrayList k = new ArrayList();
    public final ArrayList l = new ArrayList();

    public g(p pVar) {
        this.d = pVar;
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.e
    public final void a(e eVar) {
        ArrayList arrayList = this.l;
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            if (!((g) it2.next()).j) {
                return;
            }
        }
        this.c = true;
        p pVar = this.a;
        if (pVar != null) {
            pVar.a(this);
        }
        if (this.b) {
            this.d.a(this);
            return;
        }
        Iterator it3 = arrayList.iterator();
        g gVar = null;
        int i = 0;
        while (it3.hasNext()) {
            g gVar2 = (g) it3.next();
            if (!(gVar2 instanceof h)) {
                i++;
                gVar = gVar2;
            }
        }
        if (gVar != null && i == 1 && gVar.j) {
            h hVar = this.i;
            if (hVar != null) {
                if (!hVar.j) {
                    return;
                } else {
                    this.f = this.h * hVar.g;
                }
            }
            d(gVar.g + this.f);
        }
        p pVar2 = this.a;
        if (pVar2 != null) {
            pVar2.a(this);
        }
    }

    public final void b(p pVar) {
        this.k.add(pVar);
        if (this.j) {
            pVar.a(pVar);
        }
    }

    public final void c() {
        this.l.clear();
        this.k.clear();
        this.j = false;
        this.g = 0;
        this.c = false;
        this.b = false;
    }

    public void d(int i) {
        if (this.j) {
            return;
        }
        this.j = true;
        this.g = i;
        Iterator it2 = this.k.iterator();
        while (it2.hasNext()) {
            e eVar = (e) it2.next();
            eVar.a(eVar);
        }
    }

    public final String toString() {
        String str;
        StringBuilder sb = new StringBuilder();
        sb.append(this.d.b.l0);
        sb.append(":");
        switch (this.e) {
            case 1:
                str = "UNKNOWN";
                break;
            case 2:
                str = "HORIZONTAL_DIMENSION";
                break;
            case 3:
                str = "VERTICAL_DIMENSION";
                break;
            case 4:
                str = "LEFT";
                break;
            case 5:
                str = "RIGHT";
                break;
            case 6:
                str = "TOP";
                break;
            case 7:
                str = "BOTTOM";
                break;
            case 8:
                str = "BASELINE";
                break;
            default:
                str = "null";
                break;
        }
        sb.append(str);
        sb.append("(");
        sb.append(this.j ? Integer.valueOf(this.g) : "unresolved");
        sb.append(") <t=");
        sb.append(this.l.size());
        sb.append(":d=");
        sb.append(this.k.size());
        sb.append(SimpleComparison.GREATER_THAN_OPERATION);
        return sb.toString();
    }
}

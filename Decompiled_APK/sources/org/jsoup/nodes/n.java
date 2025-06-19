package org.jsoup.nodes;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3394t2;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Pattern;
import org.jsoup.helper.ValidationException;

/* loaded from: classes3.dex */
public abstract class n implements Cloneable {
    public static final List c = Collections.EMPTY_LIST;
    public n a;
    public int b;

    public static void p(StringBuilder sb, int i, f fVar) {
        String strValueOf;
        Appendable appendableAppend = sb.append('\n');
        int iMin = i * fVar.f;
        String[] strArr = org.jsoup.internal.a.a;
        if (!(iMin >= 0)) {
            throw new ValidationException("width must be >= 0");
        }
        int i2 = fVar.g;
        org.jsoup.helper.b.d(i2 >= -1);
        if (i2 != -1) {
            iMin = Math.min(iMin, i2);
        }
        if (iMin < 21) {
            strValueOf = org.jsoup.internal.a.a[iMin];
        } else {
            char[] cArr = new char[iMin];
            for (int i3 = 0; i3 < iMin; i3++) {
                cArr[i3] = ' ';
            }
            strValueOf = String.valueOf(cArr);
        }
        appendableAppend.append(strValueOf);
    }

    public n A() {
        n nVar = this;
        while (true) {
            n nVar2 = nVar.a;
            if (nVar2 == null) {
                return nVar;
            }
            nVar = nVar2;
        }
    }

    public String b(String str) {
        org.jsoup.helper.b.e(str);
        if (!o() || e().o(str) == -1) {
            return "";
        }
        String strF = f();
        String strK = e().k(str);
        Pattern pattern = org.jsoup.internal.a.d;
        String strReplaceAll = pattern.matcher(strF).replaceAll("");
        String strReplaceAll2 = pattern.matcher(strK).replaceAll("");
        try {
            try {
                return org.jsoup.internal.a.h(new URL(strReplaceAll), strReplaceAll2).toExternalForm();
            } catch (MalformedURLException unused) {
                return new URL(strReplaceAll2).toExternalForm();
            }
        } catch (MalformedURLException unused2) {
            return org.jsoup.internal.a.c.matcher(strReplaceAll2).find() ? strReplaceAll2 : "";
        }
    }

    public final void c(int i, n... nVarArr) {
        org.jsoup.helper.b.g(nVarArr);
        if (nVarArr.length == 0) {
            return;
        }
        List listM = m();
        n nVarW = nVarArr[0].w();
        if (nVarW != null && nVarW.g() == nVarArr.length) {
            List listM2 = nVarW.m();
            int length = nVarArr.length;
            while (true) {
                int i2 = length - 1;
                if (length <= 0) {
                    boolean z = g() == 0;
                    nVarW.l();
                    listM.addAll(i, Arrays.asList(nVarArr));
                    int length2 = nVarArr.length;
                    while (true) {
                        int i3 = length2 - 1;
                        if (length2 <= 0) {
                            break;
                        }
                        nVarArr[i3].a = this;
                        length2 = i3;
                    }
                    if (z && nVarArr[0].b == 0) {
                        return;
                    }
                    x(i);
                    return;
                }
                if (nVarArr[i2] != listM2.get(i2)) {
                    break;
                } else {
                    length = i2;
                }
            }
        }
        for (n nVar : nVarArr) {
            if (nVar == null) {
                throw new ValidationException("Array must not contain any null objects");
            }
        }
        for (n nVar2 : nVarArr) {
            nVar2.getClass();
            n nVar3 = nVar2.a;
            if (nVar3 != null) {
                nVar3.z(nVar2);
            }
            nVar2.a = this;
        }
        listM.addAll(i, Arrays.asList(nVarArr));
        x(i);
    }

    public String d(String str) {
        org.jsoup.helper.b.g(str);
        if (!o()) {
            return "";
        }
        String strK = e().k(str);
        return strK.length() > 0 ? strK : str.startsWith("abs:") ? b(str.substring(4)) : "";
    }

    public abstract b e();

    public final boolean equals(Object obj) {
        return this == obj;
    }

    public abstract String f();

    public abstract int g();

    public final List h() {
        if (g() == 0) {
            return c;
        }
        List listM = m();
        ArrayList arrayList = new ArrayList(listM.size());
        arrayList.addAll(listM);
        return Collections.unmodifiableList(arrayList);
    }

    @Override // 
    public n i() {
        n nVarK = k(null);
        LinkedList linkedList = new LinkedList();
        linkedList.add(nVarK);
        while (!linkedList.isEmpty()) {
            n nVar = (n) linkedList.remove();
            int iG = nVar.g();
            for (int i = 0; i < iG; i++) {
                List listM = nVar.m();
                n nVarK2 = ((n) listM.get(i)).k(nVar);
                listM.set(i, nVarK2);
                linkedList.add(nVarK2);
            }
        }
        return nVarK;
    }

    public n k(n nVar) {
        g gVarV;
        try {
            n nVar2 = (n) super.clone();
            nVar2.a = nVar;
            nVar2.b = nVar == null ? 0 : this.b;
            if (nVar == null && !(this instanceof g) && (gVarV = v()) != null) {
                g gVar = new g(gVarV.f());
                b bVar = gVarV.g;
                if (bVar != null) {
                    gVar.g = bVar.clone();
                }
                gVar.j = gVarV.j.clone();
                nVar2.a = gVar;
                gVar.m().add(nVar2);
            }
            return nVar2;
        } catch (CloneNotSupportedException e) {
            throw new RuntimeException(e);
        }
    }

    public abstract n l();

    public abstract List m();

    public final boolean n(String str) {
        org.jsoup.helper.b.g(str);
        if (!o()) {
            return false;
        }
        if (str.startsWith("abs:")) {
            String strSubstring = str.substring(4);
            if (e().o(strSubstring) != -1 && !b(strSubstring).isEmpty()) {
                return true;
            }
        }
        return e().o(str) != -1;
    }

    public abstract boolean o();

    public final n q() {
        n nVar = this.a;
        if (nVar == null) {
            return null;
        }
        List listM = nVar.m();
        int i = this.b + 1;
        if (listM.size() > i) {
            return (n) listM.get(i);
        }
        return null;
    }

    public abstract String r();

    public String s() {
        StringBuilder sbB = org.jsoup.internal.a.b();
        g gVarV = v();
        if (gVarV == null) {
            gVarV = new g("");
        }
        AbstractC3394t2.j(new com.quizlet.remote.model.user.emailconfirmation.c(sbB, gVarV.j), this);
        return org.jsoup.internal.a.g(sbB);
    }

    public abstract void t(StringBuilder sb, int i, f fVar);

    public String toString() {
        return s();
    }

    public abstract void u(StringBuilder sb, int i, f fVar);

    public final g v() {
        n nVarA = A();
        if (nVarA instanceof g) {
            return (g) nVarA;
        }
        return null;
    }

    public n w() {
        return this.a;
    }

    public final void x(int i) {
        int iG = g();
        if (iG == 0) {
            return;
        }
        List listM = m();
        while (i < iG) {
            ((n) listM.get(i)).b = i;
            i++;
        }
    }

    public final void y() {
        org.jsoup.helper.b.g(this.a);
        this.a.z(this);
    }

    public void z(n nVar) {
        org.jsoup.helper.b.d(nVar.a == this);
        int i = nVar.b;
        m().remove(i);
        x(i);
        nVar.a = null;
    }
}

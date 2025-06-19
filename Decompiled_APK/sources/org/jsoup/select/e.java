package org.jsoup.select;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3386r2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3394t2;
import com.quizlet.db.data.models.base.AssociationNames;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import org.wordpress.aztec.E;

/* loaded from: classes3.dex */
public final class e extends m {
    public final /* synthetic */ int a;
    public final String b;

    public /* synthetic */ e(String str, int i, boolean z) {
        this.a = i;
        this.b = str;
    }

    @Override // org.jsoup.select.m
    public final boolean a(org.jsoup.nodes.i iVar, org.jsoup.nodes.i iVar2) {
        switch (this.a) {
            case 0:
                return iVar2.n(this.b);
            case 1:
                org.jsoup.nodes.b bVarE = iVar2.e();
                bVarE.getClass();
                ArrayList arrayList = new ArrayList(bVarE.a);
                for (int i = 0; i < bVarE.a; i++) {
                    if (!org.jsoup.nodes.b.r(bVarE.b[i])) {
                        arrayList.add(new org.jsoup.nodes.a(bVarE.b[i], (String) bVarE.c[i], bVarE));
                    }
                }
                Iterator it2 = Collections.unmodifiableList(arrayList).iterator();
                while (it2.hasNext()) {
                    if (AbstractC3386r2.c(((org.jsoup.nodes.a) it2.next()).a).startsWith(this.b)) {
                        return true;
                    }
                }
                return false;
            case 2:
                org.jsoup.nodes.b bVar = iVar2.g;
                if (bVar == null) {
                    return false;
                }
                String strK = bVar.k(AssociationNames.CLASS);
                int length = strK.length();
                String str = this.b;
                int length2 = str.length();
                if (length == 0 || length < length2) {
                    return false;
                }
                if (length == length2) {
                    return str.equalsIgnoreCase(strK);
                }
                boolean z = false;
                int i2 = 0;
                for (int i3 = 0; i3 < length; i3++) {
                    if (Character.isWhitespace(strK.charAt(i3))) {
                        if (!z) {
                            continue;
                        } else {
                            if (i3 - i2 == length2 && strK.regionMatches(true, i2, str, 0, length2)) {
                                return true;
                            }
                            z = false;
                        }
                    } else if (!z) {
                        i2 = i3;
                        z = true;
                    }
                }
                if (z && length - i2 == length2) {
                    return strK.regionMatches(true, i2, str, 0, length2);
                }
                return false;
            case 3:
                return AbstractC3386r2.c(iVar2.I()).contains(this.b);
            case 4:
                return AbstractC3386r2.c(iVar2.O()).contains(this.b);
            case 5:
                iVar2.getClass();
                StringBuilder sbB = org.jsoup.internal.a.b();
                AbstractC3394t2.j(new E(sbB), iVar2);
                return AbstractC3386r2.c(org.jsoup.internal.a.g(sbB).trim()).contains(this.b);
            case 6:
                return iVar2.U().contains(this.b);
            case 7:
                iVar2.getClass();
                StringBuilder sbB2 = org.jsoup.internal.a.b();
                AbstractC3394t2.j(new com.quizlet.infra.legacysyncengine.tasks.parse.b(sbB2, 28), iVar2);
                return org.jsoup.internal.a.g(sbB2).contains(this.b);
            case 8:
                org.jsoup.nodes.b bVar2 = iVar2.g;
                return this.b.equals(bVar2 != null ? bVar2.k("id") : "");
            case 9:
                return iVar2.d.b.equals(this.b);
            default:
                return iVar2.d.b.endsWith(this.b);
        }
    }

    public final String toString() {
        switch (this.a) {
            case 0:
                return android.support.v4.media.session.a.t(new StringBuilder("["), this.b, "]");
            case 1:
                return android.support.v4.media.session.a.t(new StringBuilder("[^"), this.b, "]");
            case 2:
                return "." + this.b;
            case 3:
                return android.support.v4.media.session.a.t(new StringBuilder(":containsData("), this.b, ")");
            case 4:
                return android.support.v4.media.session.a.t(new StringBuilder(":containsOwn("), this.b, ")");
            case 5:
                return android.support.v4.media.session.a.t(new StringBuilder(":contains("), this.b, ")");
            case 6:
                return android.support.v4.media.session.a.t(new StringBuilder(":containsWholeOwnText("), this.b, ")");
            case 7:
                return android.support.v4.media.session.a.t(new StringBuilder(":containsWholeText("), this.b, ")");
            case 8:
                return "#" + this.b;
            case 9:
                return this.b;
            default:
                return this.b;
        }
    }

    public e(String str, int i) {
        this.a = i;
        switch (i) {
            case 3:
                this.b = AbstractC3386r2.c(str);
                break;
            case 4:
                StringBuilder sbB = org.jsoup.internal.a.b();
                org.jsoup.internal.a.a(str, sbB, false);
                this.b = AbstractC3386r2.c(org.jsoup.internal.a.g(sbB));
                break;
            case 5:
                StringBuilder sbB2 = org.jsoup.internal.a.b();
                org.jsoup.internal.a.a(str, sbB2, false);
                this.b = AbstractC3386r2.c(org.jsoup.internal.a.g(sbB2));
                break;
            default:
                org.jsoup.helper.b.e(str);
                this.b = AbstractC3386r2.c(str);
                break;
        }
    }
}

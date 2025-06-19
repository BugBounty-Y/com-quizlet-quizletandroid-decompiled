package org.jsoup.select;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3386r2;
import com.j256.ormlite.stmt.query.SimpleComparison;

/* loaded from: classes3.dex */
public final class f extends m {
    public final String a;
    public final String b;
    public final /* synthetic */ int c;

    public f(String str, int i, String str2, boolean z) {
        this.c = i;
        org.jsoup.helper.b.e(str);
        org.jsoup.helper.b.e(str2);
        this.a = AbstractC3386r2.d(str);
        boolean z2 = (str2.startsWith("'") && str2.endsWith("'")) || (str2.startsWith("\"") && str2.endsWith("\""));
        str2 = z2 ? str2.substring(1, str2.length() - 1) : str2;
        String strC = (!z && z2) ? AbstractC3386r2.c(str2) : AbstractC3386r2.d(str2);
        this.b = strC;
    }

    @Override // org.jsoup.select.m
    public final boolean a(org.jsoup.nodes.i iVar, org.jsoup.nodes.i iVar2) {
        switch (this.c) {
            case 0:
                String str = this.a;
                if (iVar2.n(str)) {
                    if (this.b.equalsIgnoreCase(iVar2.d(str).trim())) {
                        return true;
                    }
                }
                return false;
            case 1:
                String str2 = this.a;
                return iVar2.n(str2) && AbstractC3386r2.c(iVar2.d(str2)).contains(this.b);
            case 2:
                String str3 = this.a;
                return iVar2.n(str3) && AbstractC3386r2.c(iVar2.d(str3)).endsWith(this.b);
            case 3:
                return !this.b.equalsIgnoreCase(iVar2.d(this.a));
            default:
                String str4 = this.a;
                return iVar2.n(str4) && AbstractC3386r2.c(iVar2.d(str4)).startsWith(this.b);
        }
    }

    public final String toString() {
        switch (this.c) {
            case 0:
                StringBuilder sb = new StringBuilder("[");
                sb.append(this.a);
                sb.append(SimpleComparison.EQUAL_TO_OPERATION);
                return android.support.v4.media.session.a.t(sb, this.b, "]");
            case 1:
                StringBuilder sb2 = new StringBuilder("[");
                sb2.append(this.a);
                sb2.append("*=");
                return android.support.v4.media.session.a.t(sb2, this.b, "]");
            case 2:
                StringBuilder sb3 = new StringBuilder("[");
                sb3.append(this.a);
                sb3.append("$=");
                return android.support.v4.media.session.a.t(sb3, this.b, "]");
            case 3:
                StringBuilder sb4 = new StringBuilder("[");
                sb4.append(this.a);
                sb4.append("!=");
                return android.support.v4.media.session.a.t(sb4, this.b, "]");
            default:
                StringBuilder sb5 = new StringBuilder("[");
                sb5.append(this.a);
                sb5.append("^=");
                return android.support.v4.media.session.a.t(sb5, this.b, "]");
        }
    }
}

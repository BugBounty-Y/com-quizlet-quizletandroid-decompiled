package com.onetrust.otpublishers.headless.UI.UIProperty;

import androidx.compose.runtime.internal.j;
import androidx.constraintlayout.motion.widget.n;
import androidx.navigation.internal.m;
import androidx.webkit.internal.p;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3633h4;

/* loaded from: classes2.dex */
public final class g {
    public String a;
    public String b;
    public String c;
    public String d;
    public String e;
    public String f;
    public String g;
    public String h;
    public String i;
    public String q;
    public m j = new m();
    public m k = new m();
    public m l = new m();
    public m m = new m();
    public j n = new j();
    public n o = new n();
    public n p = new n();
    public p r = new p(27);
    public final androidx.camera.camera2.internal.compat.workaround.b s = new androidx.camera.camera2.internal.compat.workaround.b();
    public final io.ktor.client.plugins.api.d t = new io.ktor.client.plugins.api.d(9);

    public final String toString() {
        StringBuilder sb = new StringBuilder("OTVendorListUIProperty{backgroundColor='");
        sb.append(this.a);
        sb.append("', lineBreakColor='");
        sb.append(this.b);
        sb.append("', toggleThumbColorOn='");
        sb.append(this.c);
        sb.append("', toggleThumbColorOff='");
        sb.append(this.d);
        sb.append("', toggleTrackColor='");
        sb.append(this.e);
        sb.append("', filterOnColor='");
        sb.append(this.f);
        sb.append("', filterOffColor='");
        sb.append(this.g);
        sb.append("', rightChevronColor='");
        sb.append(this.i);
        sb.append("', filterSelectionColor='");
        sb.append(this.h);
        sb.append("', filterNavTextProperty=");
        AbstractC3633h4.a(this.j, sb, ", titleTextProperty=");
        AbstractC3633h4.a(this.k, sb, ", allowAllToggleTextProperty=");
        AbstractC3633h4.a(this.l, sb, ", filterItemTitleTextProperty=");
        AbstractC3633h4.a(this.m, sb, ", searchBarProperty=");
        sb.append(this.n.toString());
        sb.append(", confirmMyChoiceProperty=");
        sb.append(this.o.toString());
        sb.append(", applyFilterButtonProperty=");
        sb.append(this.p.toString());
        sb.append(", backButtonColor='");
        sb.append(this.q);
        sb.append("', pageHeaderProperty=");
        sb.append(this.r.toString());
        sb.append(", backIconProperty=");
        sb.append(this.s.toString());
        sb.append(", filterIconProperty=");
        sb.append(this.t.toString());
        sb.append('}');
        return sb.toString();
    }
}

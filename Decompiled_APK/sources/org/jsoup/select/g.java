package org.jsoup.select;

import androidx.compose.ui.node.B;
import java.util.regex.Pattern;

/* loaded from: classes3.dex */
public final class g extends m {
    public String a;
    public Pattern b;

    @Override // org.jsoup.select.m
    public final boolean a(org.jsoup.nodes.i iVar, org.jsoup.nodes.i iVar2) {
        String str = this.a;
        return iVar2.n(str) && this.b.matcher(iVar2.d(str)).find();
    }

    public final String toString() {
        return B.j(new StringBuilder("["), this.a, "~=", this.b.toString(), "]");
    }
}

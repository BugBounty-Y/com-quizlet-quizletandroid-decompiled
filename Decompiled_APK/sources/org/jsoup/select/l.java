package org.jsoup.select;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3394t2;
import java.util.regex.Pattern;
import org.wordpress.aztec.E;

/* loaded from: classes3.dex */
public final class l extends m {
    public final /* synthetic */ int a;
    public final Pattern b;

    public /* synthetic */ l(Pattern pattern, int i) {
        this.a = i;
        this.b = pattern;
    }

    @Override // org.jsoup.select.m
    public final boolean a(org.jsoup.nodes.i iVar, org.jsoup.nodes.i iVar2) {
        switch (this.a) {
            case 0:
                iVar2.getClass();
                StringBuilder sbB = org.jsoup.internal.a.b();
                AbstractC3394t2.j(new E(sbB), iVar2);
                return this.b.matcher(org.jsoup.internal.a.g(sbB).trim()).find();
            case 1:
                return this.b.matcher(iVar2.O()).find();
            case 2:
                return this.b.matcher(iVar2.U()).find();
            default:
                iVar2.getClass();
                StringBuilder sbB2 = org.jsoup.internal.a.b();
                AbstractC3394t2.j(new com.quizlet.infra.legacysyncengine.tasks.parse.b(sbB2, 28), iVar2);
                return this.b.matcher(org.jsoup.internal.a.g(sbB2)).find();
        }
    }

    public final String toString() {
        switch (this.a) {
            case 0:
                return ":matches(" + this.b + ")";
            case 1:
                return ":matchesOwn(" + this.b + ")";
            case 2:
                return ":matchesWholeOwnText(" + this.b + ")";
            default:
                return ":matchesWholeText(" + this.b + ")";
        }
    }
}

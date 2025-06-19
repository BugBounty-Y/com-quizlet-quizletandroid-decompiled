package org.jsoup.parser;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3386r2;

/* loaded from: classes3.dex */
public final class D {
    public static final D c = new D(false, false);
    public static final D d = new D(true, true);
    public final boolean a;
    public final boolean b;

    public D(boolean z, boolean z2) {
        this.a = z;
        this.b = z2;
    }

    public final void a(org.jsoup.nodes.b bVar) {
        if (bVar == null || this.b) {
            return;
        }
        for (int i = 0; i < bVar.a; i++) {
            String[] strArr = bVar.b;
            strArr[i] = AbstractC3386r2.c(strArr[i]);
        }
    }

    public final String b(String str) {
        String strTrim = str.trim();
        return !this.a ? AbstractC3386r2.c(strTrim) : strTrim;
    }
}

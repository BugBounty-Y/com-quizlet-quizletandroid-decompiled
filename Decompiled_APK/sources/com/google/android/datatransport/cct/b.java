package com.google.android.datatransport.cct;

import android.content.Context;
import android.net.ConnectivityManager;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.webkit.internal.p;
import com.google.android.datatransport.cct.internal.AbstractC1571a;
import com.google.android.datatransport.cct.internal.B;
import com.google.android.datatransport.cct.internal.C;
import com.google.android.datatransport.cct.internal.C1572b;
import com.google.android.datatransport.cct.internal.C1573c;
import com.google.android.datatransport.cct.internal.C1574d;
import com.google.android.datatransport.cct.internal.C1575e;
import com.google.android.datatransport.cct.internal.C1576f;
import com.google.android.datatransport.cct.internal.C1577g;
import com.google.android.datatransport.cct.internal.C1578h;
import com.google.android.datatransport.cct.internal.C1579i;
import com.google.android.datatransport.cct.internal.C1580j;
import com.google.android.datatransport.cct.internal.C1581k;
import com.google.android.datatransport.cct.internal.D;
import com.google.android.datatransport.cct.internal.E;
import com.google.android.datatransport.cct.internal.F;
import com.google.android.datatransport.cct.internal.G;
import com.google.android.datatransport.cct.internal.J;
import com.google.android.datatransport.cct.internal.l;
import com.google.android.datatransport.cct.internal.m;
import com.google.android.datatransport.cct.internal.n;
import com.google.android.datatransport.cct.internal.o;
import com.google.android.datatransport.cct.internal.q;
import com.google.android.datatransport.cct.internal.r;
import com.google.android.datatransport.cct.internal.t;
import com.google.android.datatransport.cct.internal.u;
import com.google.android.datatransport.cct.internal.w;
import com.google.android.datatransport.cct.internal.x;
import com.google.android.datatransport.cct.internal.z;
import com.google.android.datatransport.runtime.backends.h;
import com.google.firebase.encoders.json.d;
import java.net.MalformedURLException;
import java.net.URL;

/* loaded from: classes2.dex */
public final class b implements h {
    public final p a;
    public final ConnectivityManager b;
    public final Context c;
    public final URL d;
    public final com.google.android.datatransport.runtime.time.a e;
    public final com.google.android.datatransport.runtime.time.a f;
    public final int g;

    public b(Context context, com.google.android.datatransport.runtime.time.a aVar, com.google.android.datatransport.runtime.time.a aVar2) {
        d dVar = new d();
        C1573c c1573c = C1573c.a;
        dVar.g(x.class, c1573c);
        dVar.g(m.class, c1573c);
        C1580j c1580j = C1580j.a;
        dVar.g(G.class, c1580j);
        dVar.g(u.class, c1580j);
        C1574d c1574d = C1574d.a;
        dVar.g(z.class, c1574d);
        dVar.g(n.class, c1574d);
        C1572b c1572b = C1572b.a;
        dVar.g(AbstractC1571a.class, c1572b);
        dVar.g(l.class, c1572b);
        C1579i c1579i = C1579i.a;
        dVar.g(F.class, c1579i);
        dVar.g(t.class, c1579i);
        C1575e c1575e = C1575e.a;
        dVar.g(B.class, c1575e);
        dVar.g(o.class, c1575e);
        C1578h c1578h = C1578h.a;
        dVar.g(E.class, c1578h);
        dVar.g(r.class, c1578h);
        C1577g c1577g = C1577g.a;
        dVar.g(D.class, c1577g);
        dVar.g(q.class, c1577g);
        C1581k c1581k = C1581k.a;
        dVar.g(J.class, c1581k);
        dVar.g(w.class, c1581k);
        C1576f c1576f = C1576f.a;
        dVar.g(C.class, c1576f);
        dVar.g(com.google.android.datatransport.cct.internal.p.class, c1576f);
        dVar.d = true;
        this.a = new p(dVar, 25);
        this.c = context;
        this.b = (ConnectivityManager) context.getSystemService("connectivity");
        this.d = b(a.c);
        this.e = aVar2;
        this.f = aVar;
        this.g = 130000;
    }

    public static URL b(String str) {
        try {
            return new URL(str);
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException(AbstractC0147y.d("Invalid url: ", str), e);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x00af  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x010f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.android.datatransport.runtime.h a(com.google.android.datatransport.runtime.h r7) {
        /*
            Method dump skipped, instructions count: 295
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.datatransport.cct.b.a(com.google.android.datatransport.runtime.h):com.google.android.datatransport.runtime.h");
    }
}

package androidx.compose.foundation.text.selection;

import androidx.compose.ui.text.C0995g;

/* renamed from: androidx.compose.foundation.text.selection.m, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0532m {
    public final long a;
    public final androidx.compose.foundation.text.modifiers.g b;
    public final androidx.compose.foundation.text.modifiers.g c;
    public androidx.compose.ui.text.H d;
    public int e = -1;

    public C0532m(long j, androidx.compose.foundation.text.modifiers.g gVar, androidx.compose.foundation.text.modifiers.g gVar2) {
        this.a = j;
        this.b = gVar;
        this.c = gVar2;
    }

    public final long a(C0536q c0536q, boolean z) {
        androidx.compose.ui.text.H h;
        C0535p c0535p = c0536q.a;
        long j = this.a;
        if (z && c0535p.c != j) {
            return 9205357640488583168L;
        }
        C0535p c0535p2 = c0536q.b;
        if ((!z && c0535p2.c != j) || c() == null || (h = (androidx.compose.ui.text.H) this.c.invoke()) == null) {
            return 9205357640488583168L;
        }
        return W.t(h, kotlin.ranges.l.c(z ? c0535p.b : c0535p2.b, 0, b(h)), z, c0536q.c);
    }

    public final synchronized int b(androidx.compose.ui.text.H h) {
        try {
            if (this.d != h) {
                androidx.compose.ui.text.o oVar = h.b;
                boolean z = oVar.c;
                int i = 0;
                if (!(z || ((float) ((int) (h.c & 4294967295L))) < oVar.e) || z) {
                    i = oVar.f - 1;
                } else {
                    int iC = oVar.c((int) (h.c & 4294967295L));
                    int i2 = h.b.f - 1;
                    if (iC > i2) {
                        iC = i2;
                    }
                    while (iC >= 0 && h.b.d(iC) >= ((int) (h.c & 4294967295L))) {
                        iC--;
                    }
                    if (iC >= 0) {
                        i = iC;
                    }
                }
                this.e = h.e(i, true);
                this.d = h;
            }
        } catch (Throwable th) {
            throw th;
        }
        return this.e;
    }

    public final androidx.compose.ui.layout.r c() {
        androidx.compose.ui.layout.r rVar = (androidx.compose.ui.layout.r) this.b.invoke();
        if (rVar == null || !rVar.k()) {
            return null;
        }
        return rVar;
    }

    public final C0536q d() {
        androidx.compose.ui.text.H h = (androidx.compose.ui.text.H) this.c.invoke();
        if (h == null) {
            return null;
        }
        int length = h.a.a.a.length();
        androidx.compose.ui.text.style.h hVarA = h.a(0);
        long j = this.a;
        return new C0536q(new C0535p(hVarA, 0, j), new C0535p(h.a(Math.max(length - 1, 0)), length, j), false);
    }

    public final C0995g e() {
        androidx.compose.ui.text.H h = (androidx.compose.ui.text.H) this.c.invoke();
        return h == null ? new C0995g(6, "", null) : h.a.a;
    }
}

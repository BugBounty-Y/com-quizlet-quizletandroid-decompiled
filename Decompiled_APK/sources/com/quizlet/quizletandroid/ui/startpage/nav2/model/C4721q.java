package com.quizlet.quizletandroid.ui.startpage.nav2.model;

import java.util.ArrayList;
import java.util.List;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.model.q, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4721q {
    public List a;
    public List b;
    public List c;
    public List d;
    public List e;
    public List f;
    public List g;
    public List h;
    public List i;
    public List j;
    public List k;
    public List l;
    public List m;
    public List n;
    public final ArrayList o = new ArrayList();

    public static void e(int i, List list) {
        if (list.isEmpty()) {
            return;
        }
        int i2 = 0;
        for (Object obj : list) {
            int i3 = i2 + 1;
            if (i2 < 0) {
                kotlin.collections.B.p();
                throw null;
            }
            AbstractC4707c abstractC4707c = (AbstractC4707c) obj;
            abstractC4707c.c = i2;
            abstractC4707c.b = i;
            i2 = i3;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:52:0x00e9 A[PHI: r1
  0x00e9: PHI (r1v53 java.lang.Integer) = (r1v46 java.lang.Integer), (r1v50 java.lang.Integer) binds: [B:51:0x00e7, B:57:0x00fc] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.util.List a() {
        /*
            Method dump skipped, instructions count: 898
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.startpage.nav2.model.C4721q.a():java.util.List");
    }

    public final List b() {
        List list = this.f;
        return list == null ? kotlin.collections.K.a : list;
    }

    public final boolean c() {
        return (this.a == null && this.b == null && this.c == null && this.d == null && this.e == null && this.f == null && this.h == null) ? false : true;
    }

    public final void d(List list, EnumC4720p enumC4720p) {
        if (list == null || !(!list.isEmpty())) {
            return;
        }
        this.o.add(enumC4720p);
    }
}

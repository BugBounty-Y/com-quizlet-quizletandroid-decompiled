package com.airbnb.lottie.model.layer;

import androidx.compose.animation.d0;
import androidx.webkit.internal.p;
import java.util.List;
import java.util.Locale;

/* loaded from: classes.dex */
public final class e {
    public final List a;
    public final com.airbnb.lottie.h b;
    public final String c;
    public final long d;
    public final int e;
    public final long f;
    public final String g;
    public final List h;
    public final com.airbnb.lottie.model.animatable.e i;
    public final int j;
    public final int k;
    public final int l;
    public final float m;
    public final float n;
    public final float o;
    public final float p;
    public final com.airbnb.lottie.model.animatable.a q;
    public final com.quizlet.data.repository.qclass.c r;
    public final com.airbnb.lottie.model.animatable.b s;
    public final List t;
    public final int u;
    public final boolean v;
    public final p w;
    public final com.quizlet.data.repository.studysetwithcreatorinclass.g x;
    public final int y;

    public e(List list, com.airbnb.lottie.h hVar, String str, long j, int i, long j2, String str2, List list2, com.airbnb.lottie.model.animatable.e eVar, int i2, int i3, int i4, float f, float f2, float f3, float f4, com.airbnb.lottie.model.animatable.a aVar, com.quizlet.data.repository.qclass.c cVar, List list3, int i5, com.airbnb.lottie.model.animatable.b bVar, boolean z, p pVar, com.quizlet.data.repository.studysetwithcreatorinclass.g gVar, int i6) {
        this.a = list;
        this.b = hVar;
        this.c = str;
        this.d = j;
        this.e = i;
        this.f = j2;
        this.g = str2;
        this.h = list2;
        this.i = eVar;
        this.j = i2;
        this.k = i3;
        this.l = i4;
        this.m = f;
        this.n = f2;
        this.o = f3;
        this.p = f4;
        this.q = aVar;
        this.r = cVar;
        this.t = list3;
        this.u = i5;
        this.s = bVar;
        this.v = z;
        this.w = pVar;
        this.x = gVar;
        this.y = i6;
    }

    public final String a(String str) {
        int i;
        StringBuilder sbU = d0.u(str);
        sbU.append(this.c);
        sbU.append("\n");
        com.airbnb.lottie.h hVar = this.b;
        e eVar = (e) hVar.i.c(this.f);
        if (eVar != null) {
            sbU.append("\t\tParents: ");
            sbU.append(eVar.c);
            for (e eVar2 = (e) hVar.i.c(eVar.f); eVar2 != null; eVar2 = (e) hVar.i.c(eVar2.f)) {
                sbU.append("->");
                sbU.append(eVar2.c);
            }
            sbU.append(str);
            sbU.append("\n");
        }
        List list = this.h;
        if (!list.isEmpty()) {
            sbU.append(str);
            sbU.append("\tMasks: ");
            sbU.append(list.size());
            sbU.append("\n");
        }
        int i2 = this.j;
        if (i2 != 0 && (i = this.k) != 0) {
            sbU.append(str);
            sbU.append("\tBackground: ");
            sbU.append(String.format(Locale.US, "%dx%d %X\n", Integer.valueOf(i2), Integer.valueOf(i), Integer.valueOf(this.l)));
        }
        List list2 = this.a;
        if (!list2.isEmpty()) {
            sbU.append(str);
            sbU.append("\tShapes:\n");
            for (Object obj : list2) {
                sbU.append(str);
                sbU.append("\t\t");
                sbU.append(obj);
                sbU.append("\n");
            }
        }
        return sbU.toString();
    }

    public final String toString() {
        return a("");
    }
}

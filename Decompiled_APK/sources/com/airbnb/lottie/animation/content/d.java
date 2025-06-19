package com.airbnb.lottie.animation.content;

import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.ColorFilter;
import android.graphics.Matrix;
import android.graphics.Path;
import android.graphics.RectF;
import com.airbnb.lottie.u;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes.dex */
public final class d implements e, m, com.airbnb.lottie.animation.keyframe.a, com.airbnb.lottie.model.f {
    public final com.android.billingclient.api.s a;
    public final RectF b;
    public final com.airbnb.lottie.utils.h c;
    public final Matrix d;
    public final Path e;
    public final RectF f;
    public final String g;
    public final boolean h;
    public final ArrayList i;
    public final u j;
    public ArrayList k;
    public final com.airbnb.lottie.animation.keyframe.q l;

    public d(u uVar, com.airbnb.lottie.model.layer.b bVar, com.airbnb.lottie.model.content.m mVar, com.airbnb.lottie.h hVar) {
        com.airbnb.lottie.model.animatable.e eVar;
        String str = mVar.a;
        List list = mVar.b;
        ArrayList arrayList = new ArrayList(list.size());
        int i = 0;
        for (int i2 = 0; i2 < list.size(); i2++) {
            c cVarA = ((com.airbnb.lottie.model.content.b) list.get(i2)).a(uVar, hVar, bVar);
            if (cVarA != null) {
                arrayList.add(cVarA);
            }
        }
        while (true) {
            if (i >= list.size()) {
                eVar = null;
                break;
            }
            com.airbnb.lottie.model.content.b bVar2 = (com.airbnb.lottie.model.content.b) list.get(i);
            if (bVar2 instanceof com.airbnb.lottie.model.animatable.e) {
                eVar = (com.airbnb.lottie.model.animatable.e) bVar2;
                break;
            }
            i++;
        }
        this(uVar, bVar, str, mVar.c, arrayList, eVar);
    }

    @Override // com.airbnb.lottie.animation.keyframe.a
    public final void a() {
        this.j.invalidateSelf();
    }

    @Override // com.airbnb.lottie.animation.content.c
    public final void b(List list, List list2) {
        int size = list.size();
        ArrayList arrayList = this.i;
        ArrayList arrayList2 = new ArrayList(arrayList.size() + size);
        arrayList2.addAll(list);
        for (int size2 = arrayList.size() - 1; size2 >= 0; size2--) {
            c cVar = (c) arrayList.get(size2);
            cVar.b(arrayList2, arrayList.subList(0, size2));
            arrayList2.add(cVar);
        }
    }

    @Override // com.airbnb.lottie.animation.content.e
    public final void c(Canvas canvas, Matrix matrix, int i, com.airbnb.lottie.utils.a aVar) {
        if (this.h) {
            return;
        }
        Matrix matrix2 = this.d;
        matrix2.set(matrix);
        com.airbnb.lottie.animation.keyframe.q qVar = this.l;
        if (qVar != null) {
            matrix2.preConcat(qVar.e());
            i = (int) (((((((com.airbnb.lottie.animation.keyframe.e) qVar.l) == null ? 100 : ((Integer) r1.e()).intValue()) / 100.0f) * i) / 255.0f) * 255.0f);
        }
        u uVar = this.j;
        boolean z = (uVar.s && i() && i != 255) || (aVar != null && uVar.t && i());
        int i2 = z ? 255 : i;
        com.airbnb.lottie.utils.h hVar = this.c;
        if (z) {
            RectF rectF = this.b;
            rectF.set(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE);
            f(rectF, matrix, true);
            com.android.billingclient.api.s sVar = this.a;
            sVar.b = i;
            if (aVar != null) {
                if (Color.alpha(aVar.d) > 0) {
                    sVar.c = aVar;
                } else {
                    sVar.c = null;
                }
                aVar = null;
            } else {
                sVar.c = null;
            }
            canvas = hVar.e(canvas, rectF, sVar);
        } else if (aVar != null) {
            com.airbnb.lottie.utils.a aVar2 = new com.airbnb.lottie.utils.a(aVar);
            aVar2.b(i2);
            aVar = aVar2;
        }
        ArrayList arrayList = this.i;
        for (int size = arrayList.size() - 1; size >= 0; size--) {
            Object obj = arrayList.get(size);
            if (obj instanceof e) {
                ((e) obj).c(canvas, matrix2, i2, aVar);
            }
        }
        if (z) {
            hVar.c();
        }
    }

    @Override // com.airbnb.lottie.model.f
    public final void d(ColorFilter colorFilter, com.quizlet.data.repository.widget.b bVar) {
        com.airbnb.lottie.animation.keyframe.q qVar = this.l;
        if (qVar != null) {
            qVar.c(colorFilter, bVar);
        }
    }

    @Override // com.airbnb.lottie.model.f
    public final void e(com.airbnb.lottie.model.e eVar, int i, ArrayList arrayList, com.airbnb.lottie.model.e eVar2) {
        String str = this.g;
        if (!eVar.c(i, str) && !"__container".equals(str)) {
            return;
        }
        if (!"__container".equals(str)) {
            com.airbnb.lottie.model.e eVar3 = new com.airbnb.lottie.model.e(eVar2);
            eVar3.a.add(str);
            if (eVar.a(i, str)) {
                com.airbnb.lottie.model.e eVar4 = new com.airbnb.lottie.model.e(eVar3);
                eVar4.b = this;
                arrayList.add(eVar4);
            }
            eVar2 = eVar3;
        }
        if (!eVar.d(i, str)) {
            return;
        }
        int iB = eVar.b(i, str) + i;
        int i2 = 0;
        while (true) {
            ArrayList arrayList2 = this.i;
            if (i2 >= arrayList2.size()) {
                return;
            }
            c cVar = (c) arrayList2.get(i2);
            if (cVar instanceof com.airbnb.lottie.model.f) {
                ((com.airbnb.lottie.model.f) cVar).e(eVar, iB, arrayList, eVar2);
            }
            i2++;
        }
    }

    @Override // com.airbnb.lottie.animation.content.e
    public final void f(RectF rectF, Matrix matrix, boolean z) {
        Matrix matrix2 = this.d;
        matrix2.set(matrix);
        com.airbnb.lottie.animation.keyframe.q qVar = this.l;
        if (qVar != null) {
            matrix2.preConcat(qVar.e());
        }
        RectF rectF2 = this.f;
        rectF2.set(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE);
        ArrayList arrayList = this.i;
        for (int size = arrayList.size() - 1; size >= 0; size--) {
            c cVar = (c) arrayList.get(size);
            if (cVar instanceof e) {
                ((e) cVar).f(rectF2, matrix2, z);
                rectF.union(rectF2);
            }
        }
    }

    public final List g() {
        if (this.k == null) {
            this.k = new ArrayList();
            int i = 0;
            while (true) {
                ArrayList arrayList = this.i;
                if (i >= arrayList.size()) {
                    break;
                }
                c cVar = (c) arrayList.get(i);
                if (cVar instanceof m) {
                    this.k.add((m) cVar);
                }
                i++;
            }
        }
        return this.k;
    }

    @Override // com.airbnb.lottie.animation.content.c
    public final String getName() {
        throw null;
    }

    @Override // com.airbnb.lottie.animation.content.m
    public final Path h() {
        Matrix matrix = this.d;
        matrix.reset();
        com.airbnb.lottie.animation.keyframe.q qVar = this.l;
        if (qVar != null) {
            matrix.set(qVar.e());
        }
        Path path = this.e;
        path.reset();
        if (!this.h) {
            ArrayList arrayList = this.i;
            for (int size = arrayList.size() - 1; size >= 0; size--) {
                c cVar = (c) arrayList.get(size);
                if (cVar instanceof m) {
                    path.addPath(((m) cVar).h(), matrix);
                }
            }
        }
        return path;
    }

    public final boolean i() {
        int i = 0;
        int i2 = 0;
        while (true) {
            ArrayList arrayList = this.i;
            if (i >= arrayList.size()) {
                return false;
            }
            if ((arrayList.get(i) instanceof e) && (i2 = i2 + 1) >= 2) {
                return true;
            }
            i++;
        }
    }

    public d(u uVar, com.airbnb.lottie.model.layer.b bVar, String str, boolean z, ArrayList arrayList, com.airbnb.lottie.model.animatable.e eVar) {
        this.a = new com.android.billingclient.api.s(7, (byte) 0);
        this.b = new RectF();
        this.c = new com.airbnb.lottie.utils.h();
        this.d = new Matrix();
        this.e = new Path();
        this.f = new RectF();
        this.g = str;
        this.j = uVar;
        this.h = z;
        this.i = arrayList;
        if (eVar != null) {
            com.airbnb.lottie.animation.keyframe.q qVar = new com.airbnb.lottie.animation.keyframe.q(eVar);
            this.l = qVar;
            qVar.a(bVar);
            qVar.b(this);
        }
        ArrayList arrayList2 = new ArrayList();
        for (int size = arrayList.size() - 1; size >= 0; size--) {
            c cVar = (c) arrayList.get(size);
            if (cVar instanceof j) {
                arrayList2.add((j) cVar);
            }
        }
        for (int size2 = arrayList2.size() - 1; size2 >= 0; size2--) {
            ((j) arrayList2.get(size2)).g(arrayList.listIterator(arrayList.size()));
        }
    }
}

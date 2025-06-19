package com.airbnb.lottie.model.layer;

import android.graphics.BlurMaskFilter;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Matrix;
import android.graphics.Path;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffXfermode;
import android.graphics.RectF;
import androidx.collection.C0204b;
import androidx.collection.C0209g;
import androidx.webkit.internal.p;
import com.airbnb.lottie.B;
import com.airbnb.lottie.animation.keyframe.q;
import com.airbnb.lottie.u;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes.dex */
public abstract class b implements com.airbnb.lottie.animation.content.e, com.airbnb.lottie.animation.keyframe.a, com.airbnb.lottie.model.f {
    public float A;
    public BlurMaskFilter B;
    public com.airbnb.lottie.animation.a C;
    public final Path a = new Path();
    public final Matrix b = new Matrix();
    public final Matrix c = new Matrix();
    public final com.airbnb.lottie.animation.a d = new com.airbnb.lottie.animation.a(1, 0);
    public final com.airbnb.lottie.animation.a e;
    public final com.airbnb.lottie.animation.a f;
    public final com.airbnb.lottie.animation.a g;
    public final com.airbnb.lottie.animation.a h;
    public final RectF i;
    public final RectF j;
    public final RectF k;
    public final RectF l;
    public final RectF m;
    public final Matrix n;
    public final u o;
    public final e p;
    public final com.quizlet.data.repository.folderwithcreator.e q;
    public final com.airbnb.lottie.animation.keyframe.i r;
    public b s;
    public b t;
    public List u;
    public final ArrayList v;
    public final q w;
    public boolean x;
    public boolean y;
    public com.airbnb.lottie.animation.a z;

    public b(u uVar, e eVar) {
        PorterDuff.Mode mode = PorterDuff.Mode.DST_IN;
        this.e = new com.airbnb.lottie.animation.a(mode);
        PorterDuff.Mode mode2 = PorterDuff.Mode.DST_OUT;
        this.f = new com.airbnb.lottie.animation.a(mode2);
        com.airbnb.lottie.animation.a aVar = new com.airbnb.lottie.animation.a(1, 0);
        this.g = aVar;
        PorterDuff.Mode mode3 = PorterDuff.Mode.CLEAR;
        com.airbnb.lottie.animation.a aVar2 = new com.airbnb.lottie.animation.a();
        aVar2.setXfermode(new PorterDuffXfermode(mode3));
        this.h = aVar2;
        this.i = new RectF();
        this.j = new RectF();
        this.k = new RectF();
        this.l = new RectF();
        this.m = new RectF();
        this.n = new Matrix();
        this.v = new ArrayList();
        this.x = true;
        this.A = DefinitionKt.NO_Float_VALUE;
        this.o = uVar;
        this.p = eVar;
        if (eVar.u == 3) {
            aVar.setXfermode(new PorterDuffXfermode(mode2));
        } else {
            aVar.setXfermode(new PorterDuffXfermode(mode));
        }
        com.airbnb.lottie.model.animatable.e eVar2 = eVar.i;
        eVar2.getClass();
        q qVar = new q(eVar2);
        this.w = qVar;
        qVar.b(this);
        List list = eVar.h;
        if (list != null && !list.isEmpty()) {
            com.quizlet.data.repository.folderwithcreator.e eVar3 = new com.quizlet.data.repository.folderwithcreator.e(list);
            this.q = eVar3;
            Iterator it2 = ((ArrayList) eVar3.b).iterator();
            while (it2.hasNext()) {
                ((com.airbnb.lottie.animation.keyframe.e) it2.next()).a(this);
            }
            Iterator it3 = ((ArrayList) this.q.c).iterator();
            while (it3.hasNext()) {
                com.airbnb.lottie.animation.keyframe.e eVar4 = (com.airbnb.lottie.animation.keyframe.e) it3.next();
                g(eVar4);
                eVar4.a(this);
            }
        }
        e eVar5 = this.p;
        if (eVar5.t.isEmpty()) {
            if (true != this.x) {
                this.x = true;
                this.o.invalidateSelf();
                return;
            }
            return;
        }
        com.airbnb.lottie.animation.keyframe.i iVar = new com.airbnb.lottie.animation.keyframe.i(eVar5.t);
        this.r = iVar;
        iVar.b = true;
        iVar.a(new com.airbnb.lottie.animation.keyframe.a() { // from class: com.airbnb.lottie.model.layer.a
            @Override // com.airbnb.lottie.animation.keyframe.a
            public final void a() {
                b bVar = this.a;
                boolean z = bVar.r.l() == 1.0f;
                if (z != bVar.x) {
                    bVar.x = z;
                    bVar.o.invalidateSelf();
                }
            }
        });
        boolean z = ((Float) this.r.e()).floatValue() == 1.0f;
        if (z != this.x) {
            this.x = z;
            this.o.invalidateSelf();
        }
        g(this.r);
    }

    @Override // com.airbnb.lottie.animation.keyframe.a
    public final void a() {
        this.o.invalidateSelf();
    }

    @Override // com.airbnb.lottie.animation.content.c
    public final void b(List list, List list2) {
    }

    /* JADX WARN: Removed duplicated region for block: B:104:0x0215  */
    /* JADX WARN: Removed duplicated region for block: B:151:0x03b8  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x011a  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x011e  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x0179  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x0185  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x01aa  */
    /* JADX WARN: Removed duplicated region for block: B:94:0x01ca  */
    /* JADX WARN: Removed duplicated region for block: B:97:0x01d7  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x01df  */
    @Override // com.airbnb.lottie.animation.content.e
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void c(android.graphics.Canvas r23, android.graphics.Matrix r24, int r25, com.airbnb.lottie.utils.a r26) {
        /*
            Method dump skipped, instructions count: 1029
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.airbnb.lottie.model.layer.b.c(android.graphics.Canvas, android.graphics.Matrix, int, com.airbnb.lottie.utils.a):void");
    }

    @Override // com.airbnb.lottie.model.f
    public void d(ColorFilter colorFilter, com.quizlet.data.repository.widget.b bVar) {
        this.w.c(colorFilter, bVar);
    }

    @Override // com.airbnb.lottie.model.f
    public final void e(com.airbnb.lottie.model.e eVar, int i, ArrayList arrayList, com.airbnb.lottie.model.e eVar2) {
        b bVar = this.s;
        e eVar3 = this.p;
        if (bVar != null) {
            String str = bVar.p.c;
            com.airbnb.lottie.model.e eVar4 = new com.airbnb.lottie.model.e(eVar2);
            eVar4.a.add(str);
            if (eVar.a(i, this.s.p.c)) {
                b bVar2 = this.s;
                com.airbnb.lottie.model.e eVar5 = new com.airbnb.lottie.model.e(eVar4);
                eVar5.b = bVar2;
                arrayList.add(eVar5);
            }
            if (eVar.c(i, this.s.p.c) && eVar.d(i, eVar3.c)) {
                this.s.p(eVar, eVar.b(i, this.s.p.c) + i, arrayList, eVar4);
            }
        }
        if (eVar.c(i, eVar3.c)) {
            String str2 = eVar3.c;
            if (!"__container".equals(str2)) {
                com.airbnb.lottie.model.e eVar6 = new com.airbnb.lottie.model.e(eVar2);
                eVar6.a.add(str2);
                if (eVar.a(i, str2)) {
                    com.airbnb.lottie.model.e eVar7 = new com.airbnb.lottie.model.e(eVar6);
                    eVar7.b = this;
                    arrayList.add(eVar7);
                }
                eVar2 = eVar6;
            }
            if (eVar.d(i, str2)) {
                p(eVar, eVar.b(i, str2) + i, arrayList, eVar2);
            }
        }
    }

    @Override // com.airbnb.lottie.animation.content.e
    public void f(RectF rectF, Matrix matrix, boolean z) {
        this.i.set(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE);
        i();
        Matrix matrix2 = this.n;
        matrix2.set(matrix);
        if (z) {
            List list = this.u;
            if (list != null) {
                for (int size = list.size() - 1; size >= 0; size--) {
                    matrix2.preConcat(((b) this.u.get(size)).w.e());
                }
            } else {
                b bVar = this.t;
                if (bVar != null) {
                    matrix2.preConcat(bVar.w.e());
                }
            }
        }
        matrix2.preConcat(this.w.e());
    }

    public final void g(com.airbnb.lottie.animation.keyframe.e eVar) {
        if (eVar == null) {
            return;
        }
        this.v.add(eVar);
    }

    public final void i() {
        if (this.u != null) {
            return;
        }
        if (this.t == null) {
            this.u = Collections.EMPTY_LIST;
            return;
        }
        this.u = new ArrayList();
        for (b bVar = this.t; bVar != null; bVar = bVar.t) {
            this.u.add(bVar);
        }
    }

    public final void j(Canvas canvas) {
        RectF rectF = this.i;
        canvas.drawRect(rectF.left - 1.0f, rectF.top - 1.0f, rectF.right + 1.0f, rectF.bottom + 1.0f, this.h);
    }

    public abstract void k(Canvas canvas, Matrix matrix, int i, com.airbnb.lottie.utils.a aVar);

    public p l() {
        return this.p.w;
    }

    public final boolean m() {
        com.quizlet.data.repository.folderwithcreator.e eVar = this.q;
        return (eVar == null || ((ArrayList) eVar.b).isEmpty()) ? false : true;
    }

    public final void n() {
        B b = this.o.a.a;
        String str = this.p.c;
        if (b.a) {
            HashMap map = b.c;
            com.airbnb.lottie.utils.f fVar = (com.airbnb.lottie.utils.f) map.get(str);
            if (fVar == null) {
                fVar = new com.airbnb.lottie.utils.f();
                map.put(str, fVar);
            }
            int i = fVar.a + 1;
            fVar.a = i;
            if (i == Integer.MAX_VALUE) {
                fVar.a = i / 2;
            }
            if (str.equals("__container")) {
                C0209g c0209g = b.b;
                c0209g.getClass();
                C0204b c0204b = new C0204b(c0209g);
                if (c0204b.hasNext()) {
                    c0204b.next().getClass();
                    throw new ClassCastException();
                }
            }
        }
    }

    public final void o(com.airbnb.lottie.animation.keyframe.e eVar) {
        this.v.remove(eVar);
    }

    public void p(com.airbnb.lottie.model.e eVar, int i, ArrayList arrayList, com.airbnb.lottie.model.e eVar2) {
    }

    public void q(boolean z) {
        if (z && this.z == null) {
            this.z = new com.airbnb.lottie.animation.a();
        }
        this.y = z;
    }

    public void r(float f) {
        q qVar = this.w;
        com.airbnb.lottie.animation.keyframe.e eVar = (com.airbnb.lottie.animation.keyframe.e) qVar.l;
        if (eVar != null) {
            eVar.i(f);
        }
        com.airbnb.lottie.animation.keyframe.e eVar2 = (com.airbnb.lottie.animation.keyframe.e) qVar.m;
        if (eVar2 != null) {
            eVar2.i(f);
        }
        com.airbnb.lottie.animation.keyframe.e eVar3 = (com.airbnb.lottie.animation.keyframe.e) qVar.n;
        if (eVar3 != null) {
            eVar3.i(f);
        }
        com.airbnb.lottie.animation.keyframe.e eVar4 = (com.airbnb.lottie.animation.keyframe.e) qVar.h;
        if (eVar4 != null) {
            eVar4.i(f);
        }
        com.airbnb.lottie.animation.keyframe.e eVar5 = (com.airbnb.lottie.animation.keyframe.e) qVar.i;
        if (eVar5 != null) {
            eVar5.i(f);
        }
        com.airbnb.lottie.animation.keyframe.e eVar6 = (com.airbnb.lottie.animation.keyframe.e) qVar.j;
        if (eVar6 != null) {
            eVar6.i(f);
        }
        com.airbnb.lottie.animation.keyframe.e eVar7 = (com.airbnb.lottie.animation.keyframe.e) qVar.k;
        if (eVar7 != null) {
            eVar7.i(f);
        }
        com.airbnb.lottie.animation.keyframe.i iVar = (com.airbnb.lottie.animation.keyframe.i) qVar.o;
        if (iVar != null) {
            iVar.i(f);
        }
        com.airbnb.lottie.animation.keyframe.i iVar2 = (com.airbnb.lottie.animation.keyframe.i) qVar.p;
        if (iVar2 != null) {
            iVar2.i(f);
        }
        com.quizlet.data.repository.folderwithcreator.e eVar8 = this.q;
        int i = 0;
        if (eVar8 != null) {
            int i2 = 0;
            while (true) {
                ArrayList arrayList = (ArrayList) eVar8.b;
                if (i2 >= arrayList.size()) {
                    break;
                }
                ((com.airbnb.lottie.animation.keyframe.e) arrayList.get(i2)).i(f);
                i2++;
            }
        }
        com.airbnb.lottie.animation.keyframe.i iVar3 = this.r;
        if (iVar3 != null) {
            iVar3.i(f);
        }
        b bVar = this.s;
        if (bVar != null) {
            bVar.r(f);
        }
        while (true) {
            ArrayList arrayList2 = this.v;
            if (i >= arrayList2.size()) {
                return;
            }
            ((com.airbnb.lottie.animation.keyframe.e) arrayList2.get(i)).i(f);
            i++;
        }
    }
}

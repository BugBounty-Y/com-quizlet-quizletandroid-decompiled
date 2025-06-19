package com.airbnb.lottie.model.layer;

import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.ColorFilter;
import android.graphics.Matrix;
import android.graphics.RectF;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.collection.C0219q;
import com.airbnb.lottie.animation.keyframe.r;
import com.airbnb.lottie.u;
import com.airbnb.lottie.y;
import com.android.billingclient.api.s;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes.dex */
public final class c extends b {
    public com.airbnb.lottie.animation.keyframe.e D;
    public final ArrayList E;
    public final RectF F;
    public final RectF G;
    public final RectF H;
    public final com.airbnb.lottie.utils.h I;
    public final s J;
    public float K;
    public boolean L;
    public final com.airbnb.lottie.animation.keyframe.h M;

    public c(u uVar, e eVar, List list, com.airbnb.lottie.h hVar) {
        b bVar;
        b cVar;
        String str;
        super(uVar, eVar);
        this.E = new ArrayList();
        this.F = new RectF();
        this.G = new RectF();
        this.H = new RectF();
        this.I = new com.airbnb.lottie.utils.h();
        this.J = new s(7, (byte) 0);
        this.L = true;
        com.airbnb.lottie.model.animatable.b bVar2 = eVar.s;
        if (bVar2 != null) {
            com.airbnb.lottie.animation.keyframe.i iVarJ = bVar2.j();
            this.D = iVarJ;
            g(iVarJ);
            this.D.a(this);
        } else {
            this.D = null;
        }
        C0219q c0219q = new C0219q(hVar.j.size());
        int size = list.size() - 1;
        b bVar3 = null;
        while (true) {
            if (size < 0) {
                for (int i = 0; i < c0219q.i(); i++) {
                    b bVar4 = (b) c0219q.c(c0219q.f(i));
                    if (bVar4 != null && (bVar = (b) c0219q.c(bVar4.p.f)) != null) {
                        bVar4.t = bVar;
                    }
                }
                com.quizlet.data.repository.studysetwithcreatorinclass.g gVar = this.p.x;
                if (gVar != null) {
                    this.M = new com.airbnb.lottie.animation.keyframe.h(this, this, gVar);
                    return;
                }
                return;
            }
            e eVar2 = (e) list.get(size);
            int iK = AbstractC0147y.k(eVar2.e);
            if (iK == 0) {
                cVar = new c(uVar, eVar2, (List) hVar.c.get(eVar2.g), hVar);
            } else if (iK == 1) {
                cVar = new h(uVar, eVar2);
            } else if (iK == 2) {
                cVar = new d(uVar, eVar2);
            } else if (iK == 3) {
                cVar = new f(uVar, eVar2);
            } else if (iK == 4) {
                cVar = new g(uVar, eVar2, this, hVar);
            } else if (iK != 5) {
                switch (eVar2.e) {
                    case 1:
                        str = "PRE_COMP";
                        break;
                    case 2:
                        str = "SOLID";
                        break;
                    case 3:
                        str = "IMAGE";
                        break;
                    case 4:
                        str = "NULL";
                        break;
                    case 5:
                        str = "SHAPE";
                        break;
                    case 6:
                        str = "TEXT";
                        break;
                    case 7:
                        str = "UNKNOWN";
                        break;
                    default:
                        str = "null";
                        break;
                }
                com.airbnb.lottie.utils.c.b("Unknown layer type ".concat(str));
                cVar = null;
            } else {
                cVar = new j(uVar, eVar2);
            }
            if (cVar != null) {
                c0219q.g(cVar.p.d, cVar);
                if (bVar3 != null) {
                    bVar3.s = cVar;
                    bVar3 = null;
                } else {
                    this.E.add(0, cVar);
                    int iK2 = AbstractC0147y.k(eVar2.u);
                    if (iK2 == 1 || iK2 == 2) {
                        bVar3 = cVar;
                    }
                }
            }
            size--;
        }
    }

    @Override // com.airbnb.lottie.model.layer.b, com.airbnb.lottie.model.f
    public final void d(ColorFilter colorFilter, com.quizlet.data.repository.widget.b bVar) {
        super.d(colorFilter, bVar);
        if (colorFilter == y.z) {
            r rVar = new r(bVar, null);
            this.D = rVar;
            rVar.a(this);
            g(this.D);
            return;
        }
        com.airbnb.lottie.animation.keyframe.h hVar = this.M;
        if (colorFilter == 5 && hVar != null) {
            hVar.c.j(bVar);
            return;
        }
        if (colorFilter == y.B && hVar != null) {
            hVar.c(bVar);
            return;
        }
        if (colorFilter == y.C && hVar != null) {
            hVar.e.j(bVar);
            return;
        }
        if (colorFilter == y.D && hVar != null) {
            hVar.f.j(bVar);
        } else {
            if (colorFilter != y.E || hVar == null) {
                return;
            }
            hVar.g.j(bVar);
        }
    }

    @Override // com.airbnb.lottie.model.layer.b, com.airbnb.lottie.animation.content.e
    public final void f(RectF rectF, Matrix matrix, boolean z) {
        super.f(rectF, matrix, z);
        ArrayList arrayList = this.E;
        for (int size = arrayList.size() - 1; size >= 0; size--) {
            RectF rectF2 = this.F;
            rectF2.set(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE);
            ((b) arrayList.get(size)).f(rectF2, this.n, true);
            rectF.union(rectF2);
        }
    }

    @Override // com.airbnb.lottie.model.layer.b
    public final void k(Canvas canvas, Matrix matrix, int i, com.airbnb.lottie.utils.a aVar) {
        Canvas canvasE;
        com.airbnb.lottie.animation.keyframe.h hVar = this.M;
        boolean z = false;
        boolean z2 = (aVar == null && hVar == null) ? false : true;
        u uVar = this.o;
        boolean z3 = uVar.s;
        ArrayList arrayList = this.E;
        if ((z3 && arrayList.size() > 1 && i != 255) || (z2 && uVar.t)) {
            z = true;
        }
        int i2 = z ? 255 : i;
        if (hVar != null) {
            aVar = hVar.b(matrix, i2);
        }
        boolean z4 = this.L;
        RectF rectF = this.G;
        e eVar = this.p;
        if (z4 || !"__container".equals(eVar.c)) {
            rectF.set(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, eVar.o, eVar.p);
            matrix.mapRect(rectF);
        } else {
            rectF.setEmpty();
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                b bVar = (b) it2.next();
                RectF rectF2 = this.H;
                bVar.f(rectF2, matrix, true);
                rectF.union(rectF2);
            }
        }
        com.airbnb.lottie.utils.h hVar2 = this.I;
        if (z) {
            s sVar = this.J;
            sVar.c = null;
            sVar.b = i;
            if (aVar != null) {
                if (Color.alpha(aVar.d) > 0) {
                    sVar.c = aVar;
                } else {
                    sVar.c = null;
                }
                aVar = null;
            }
            canvasE = hVar2.e(canvas, rectF, sVar);
        } else {
            canvasE = canvas;
        }
        canvas.save();
        if (canvas.clipRect(rectF)) {
            for (int size = arrayList.size() - 1; size >= 0; size--) {
                ((b) arrayList.get(size)).c(canvasE, matrix, i2, aVar);
            }
        }
        if (z) {
            hVar2.c();
        }
        canvas.restore();
    }

    @Override // com.airbnb.lottie.model.layer.b
    public final void p(com.airbnb.lottie.model.e eVar, int i, ArrayList arrayList, com.airbnb.lottie.model.e eVar2) {
        int i2 = 0;
        while (true) {
            ArrayList arrayList2 = this.E;
            if (i2 >= arrayList2.size()) {
                return;
            }
            ((b) arrayList2.get(i2)).e(eVar, i, arrayList, eVar2);
            i2++;
        }
    }

    @Override // com.airbnb.lottie.model.layer.b
    public final void q(boolean z) {
        super.q(z);
        Iterator it2 = this.E.iterator();
        while (it2.hasNext()) {
            ((b) it2.next()).q(z);
        }
    }

    @Override // com.airbnb.lottie.model.layer.b
    public final void r(float f) {
        this.K = f;
        super.r(f);
        com.airbnb.lottie.animation.keyframe.e eVar = this.D;
        e eVar2 = this.p;
        if (eVar != null) {
            com.airbnb.lottie.h hVar = this.o.a;
            f = ((((Float) eVar.e()).floatValue() * eVar2.b.n) - eVar2.b.l) / ((hVar.m - hVar.l) + 0.01f);
        }
        if (this.D == null) {
            com.airbnb.lottie.h hVar2 = eVar2.b;
            f -= eVar2.n / (hVar2.m - hVar2.l);
        }
        if (eVar2.m != DefinitionKt.NO_Float_VALUE && !"__container".equals(eVar2.c)) {
            f /= eVar2.m;
        }
        ArrayList arrayList = this.E;
        for (int size = arrayList.size() - 1; size >= 0; size--) {
            ((b) arrayList.get(size)).r(f);
        }
    }
}

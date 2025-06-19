package com.airbnb.lottie.animation.keyframe;

import android.graphics.Color;
import android.graphics.Matrix;

/* loaded from: classes.dex */
public final class h implements a {
    public final com.airbnb.lottie.model.layer.b a;
    public final com.airbnb.lottie.model.layer.b b;
    public final f c;
    public final i d;
    public final i e;
    public final i f;
    public final i g;
    public Matrix h;

    public h(com.airbnb.lottie.model.layer.b bVar, com.airbnb.lottie.model.layer.b bVar2, com.quizlet.data.repository.studysetwithcreatorinclass.g gVar) {
        this.b = bVar;
        this.a = bVar2;
        e eVarJ = ((com.airbnb.lottie.model.animatable.a) gVar.b).j();
        this.c = (f) eVarJ;
        eVarJ.a(this);
        bVar2.g(eVarJ);
        i iVarJ = ((com.airbnb.lottie.model.animatable.b) gVar.c).j();
        this.d = iVarJ;
        iVarJ.a(this);
        bVar2.g(iVarJ);
        i iVarJ2 = ((com.airbnb.lottie.model.animatable.b) gVar.d).j();
        this.e = iVarJ2;
        iVarJ2.a(this);
        bVar2.g(iVarJ2);
        i iVarJ3 = ((com.airbnb.lottie.model.animatable.b) gVar.e).j();
        this.f = iVarJ3;
        iVarJ3.a(this);
        bVar2.g(iVarJ3);
        i iVarJ4 = ((com.airbnb.lottie.model.animatable.b) gVar.f).j();
        this.g = iVarJ4;
        iVarJ4.a(this);
        bVar2.g(iVarJ4);
    }

    @Override // com.airbnb.lottie.animation.keyframe.a
    public final void a() {
        this.b.a();
    }

    public final com.airbnb.lottie.utils.a b(Matrix matrix, int i) {
        float fL = this.e.l() * 0.017453292f;
        float fFloatValue = ((Float) this.f.e()).floatValue();
        double d = fL;
        float fSin = ((float) Math.sin(d)) * fFloatValue;
        float fCos = ((float) Math.cos(d + 3.141592653589793d)) * fFloatValue;
        float fFloatValue2 = ((Float) this.g.e()).floatValue();
        int iIntValue = ((Integer) this.c.e()).intValue();
        int iArgb = Color.argb(Math.round((((Float) this.d.e()).floatValue() * i) / 255.0f), Color.red(iIntValue), Color.green(iIntValue), Color.blue(iIntValue));
        com.airbnb.lottie.utils.a aVar = new com.airbnb.lottie.utils.a();
        aVar.a = fFloatValue2 * 0.33f;
        aVar.b = fSin;
        aVar.c = fCos;
        aVar.d = iArgb;
        aVar.e = null;
        aVar.c(matrix);
        if (this.h == null) {
            this.h = new Matrix();
        }
        this.a.w.e().invert(this.h);
        aVar.c(this.h);
        return aVar;
    }

    public final void c(com.quizlet.data.repository.widget.b bVar) {
        this.d.j(new g(bVar));
    }
}

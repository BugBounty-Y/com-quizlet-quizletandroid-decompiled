package com.airbnb.lottie.animation.keyframe;

import android.view.animation.BaseInterpolator;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes.dex */
public abstract class e {
    public final b c;
    public com.quizlet.data.repository.widget.b e;
    public final ArrayList a = new ArrayList(1);
    public boolean b = false;
    public float d = DefinitionKt.NO_Float_VALUE;
    public Object f = null;
    public float g = -1.0f;
    public float h = -1.0f;

    public e(List list) {
        b dVar;
        if (list.isEmpty()) {
            dVar = new com.google.mlkit.common.sdkinternal.b(5);
        } else {
            dVar = list.size() == 1 ? new d(list) : new c(list);
        }
        this.c = dVar;
    }

    public final void a(a aVar) {
        this.a.add(aVar);
    }

    public float b() {
        if (this.h == -1.0f) {
            this.h = this.c.e();
        }
        return this.h;
    }

    public final float c() {
        BaseInterpolator baseInterpolator;
        com.airbnb.lottie.value.a aVarB = this.c.b();
        return (aVarB == null || aVarB.c() || (baseInterpolator = aVarB.d) == null) ? DefinitionKt.NO_Float_VALUE : baseInterpolator.getInterpolation(d());
    }

    public final float d() {
        if (this.b) {
            return DefinitionKt.NO_Float_VALUE;
        }
        com.airbnb.lottie.value.a aVarB = this.c.b();
        return aVarB.c() ? DefinitionKt.NO_Float_VALUE : (this.d - aVarB.b()) / (aVarB.a() - aVarB.b());
    }

    public Object e() {
        BaseInterpolator baseInterpolator;
        float fD = d();
        com.quizlet.data.repository.widget.b bVar = this.e;
        b bVar2 = this.c;
        if (bVar == null && bVar2.a(fD) && !k()) {
            return this.f;
        }
        com.airbnb.lottie.value.a aVarB = bVar2.b();
        BaseInterpolator baseInterpolator2 = aVarB.e;
        Object objF = (baseInterpolator2 == null || (baseInterpolator = aVarB.f) == null) ? f(aVarB, c()) : g(aVarB, fD, baseInterpolator2.getInterpolation(fD), baseInterpolator.getInterpolation(fD));
        this.f = objF;
        return objF;
    }

    public abstract Object f(com.airbnb.lottie.value.a aVar, float f);

    public Object g(com.airbnb.lottie.value.a aVar, float f, float f2, float f3) {
        throw new UnsupportedOperationException("This animation does not support split dimensions!");
    }

    public void h() {
        int i = 0;
        while (true) {
            ArrayList arrayList = this.a;
            if (i >= arrayList.size()) {
                return;
            }
            ((a) arrayList.get(i)).a();
            i++;
        }
    }

    public void i(float f) {
        b bVar = this.c;
        if (bVar.isEmpty()) {
            return;
        }
        if (this.g == -1.0f) {
            this.g = bVar.i();
        }
        float f2 = this.g;
        if (f < f2) {
            if (f2 == -1.0f) {
                this.g = bVar.i();
            }
            f = this.g;
        } else if (f > b()) {
            f = b();
        }
        if (f == this.d) {
            return;
        }
        this.d = f;
        if (bVar.c(f)) {
            h();
        }
    }

    public final void j(com.quizlet.data.repository.widget.b bVar) {
        com.quizlet.data.repository.widget.b bVar2 = this.e;
        if (bVar2 != null) {
            bVar2.getClass();
        }
        this.e = bVar;
    }

    public boolean k() {
        return false;
    }
}

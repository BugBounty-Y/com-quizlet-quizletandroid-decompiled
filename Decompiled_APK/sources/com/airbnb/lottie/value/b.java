package com.airbnb.lottie.value;

import android.graphics.Matrix;
import android.graphics.Path;
import com.google.android.material.shape.m;
import com.google.android.material.shape.n;
import com.google.android.material.shape.o;
import com.google.android.material.shape.p;
import com.google.android.material.shape.q;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class b {
    public float a;
    public float b;
    public float c;
    public float d;
    public float e;
    public Object f = new ArrayList();
    public Object g = new ArrayList();

    public b() {
        e(DefinitionKt.NO_Float_VALUE, 270.0f, DefinitionKt.NO_Float_VALUE);
    }

    public void a(float f, float f2, float f3, float f4, float f5, float f6) {
        o oVar = new o(f, f2, f3, f4);
        oVar.f = f5;
        oVar.g = f6;
        ((ArrayList) this.f).add(oVar);
        m mVar = new m(oVar);
        float f7 = f5 + f6;
        boolean z = f6 < DefinitionKt.NO_Float_VALUE;
        if (z) {
            f5 = (f5 + 180.0f) % 360.0f;
        }
        float f8 = z ? (180.0f + f7) % 360.0f : f7;
        b(f5);
        ((ArrayList) this.g).add(mVar);
        this.d = f8;
        double d = f7;
        this.b = (((f3 - f) / 2.0f) * ((float) Math.cos(Math.toRadians(d)))) + ((f + f3) * 0.5f);
        this.c = (((f4 - f2) / 2.0f) * ((float) Math.sin(Math.toRadians(d)))) + ((f2 + f4) * 0.5f);
    }

    public void b(float f) {
        float f2 = this.d;
        if (f2 == f) {
            return;
        }
        float f3 = ((f - f2) + 360.0f) % 360.0f;
        if (f3 > 180.0f) {
            return;
        }
        float f4 = this.b;
        float f5 = this.c;
        o oVar = new o(f4, f5, f4, f5);
        oVar.f = this.d;
        oVar.g = f3;
        ((ArrayList) this.g).add(new m(oVar));
        this.d = f;
    }

    public void c(Matrix matrix, Path path) {
        ArrayList arrayList = (ArrayList) this.f;
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            ((q) arrayList.get(i)).a(matrix, path);
        }
    }

    public void d(float f, float f2) {
        p pVar = new p();
        pVar.b = f;
        pVar.c = f2;
        ((ArrayList) this.f).add(pVar);
        n nVar = new n(pVar, this.b, this.c);
        float fB = nVar.b() + 270.0f;
        float fB2 = nVar.b() + 270.0f;
        b(fB);
        ((ArrayList) this.g).add(nVar);
        this.d = fB2;
        this.b = f;
        this.c = f2;
    }

    public void e(float f, float f2, float f3) {
        this.a = f;
        this.b = DefinitionKt.NO_Float_VALUE;
        this.c = f;
        this.d = f2;
        this.e = (f2 + f3) % 360.0f;
        ((ArrayList) this.f).clear();
        ((ArrayList) this.g).clear();
    }
}

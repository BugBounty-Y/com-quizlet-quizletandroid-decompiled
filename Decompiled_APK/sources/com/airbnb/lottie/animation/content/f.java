package com.airbnb.lottie.animation.content;

import android.graphics.ColorFilter;
import android.graphics.Path;
import android.graphics.PointF;
import androidx.compose.ui.graphics.vector.C0868g;
import com.airbnb.lottie.u;
import com.airbnb.lottie.y;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes.dex */
public final class f implements m, com.airbnb.lottie.animation.keyframe.a, k {
    public final String b;
    public final u c;
    public final com.airbnb.lottie.animation.keyframe.j d;
    public final com.airbnb.lottie.animation.keyframe.e e;
    public final com.airbnb.lottie.model.content.a f;
    public boolean h;
    public final Path a = new Path();
    public final C0868g g = new C0868g(1);

    public f(u uVar, com.airbnb.lottie.model.layer.b bVar, com.airbnb.lottie.model.content.a aVar) {
        this.b = aVar.a;
        this.c = uVar;
        com.airbnb.lottie.animation.keyframe.e eVarJ = aVar.c.j();
        this.d = (com.airbnb.lottie.animation.keyframe.j) eVarJ;
        com.airbnb.lottie.animation.keyframe.e eVarJ2 = aVar.b.j();
        this.e = eVarJ2;
        this.f = aVar;
        bVar.g(eVarJ);
        bVar.g(eVarJ2);
        eVarJ.a(this);
        eVarJ2.a(this);
    }

    @Override // com.airbnb.lottie.animation.keyframe.a
    public final void a() {
        this.h = false;
        this.c.invalidateSelf();
    }

    @Override // com.airbnb.lottie.animation.content.c
    public final void b(List list, List list2) {
        int i = 0;
        while (true) {
            ArrayList arrayList = (ArrayList) list;
            if (i >= arrayList.size()) {
                return;
            }
            c cVar = (c) arrayList.get(i);
            if (cVar instanceof t) {
                t tVar = (t) cVar;
                if (tVar.c == 1) {
                    this.g.a.add(tVar);
                    tVar.d(this);
                }
            }
            i++;
        }
    }

    @Override // com.airbnb.lottie.model.f
    public final void d(ColorFilter colorFilter, com.quizlet.data.repository.widget.b bVar) {
        if (colorFilter == y.f) {
            this.d.j(bVar);
        } else if (colorFilter == y.i) {
            this.e.j(bVar);
        }
    }

    @Override // com.airbnb.lottie.model.f
    public final void e(com.airbnb.lottie.model.e eVar, int i, ArrayList arrayList, com.airbnb.lottie.model.e eVar2) {
        com.airbnb.lottie.utils.g.g(eVar, i, arrayList, eVar2, this);
    }

    @Override // com.airbnb.lottie.animation.content.c
    public final String getName() {
        return this.b;
    }

    @Override // com.airbnb.lottie.animation.content.m
    public final Path h() {
        boolean z = this.h;
        Path path = this.a;
        if (z) {
            return path;
        }
        path.reset();
        com.airbnb.lottie.model.content.a aVar = this.f;
        if (aVar.e) {
            this.h = true;
            return path;
        }
        PointF pointF = (PointF) this.d.e();
        float f = pointF.x / 2.0f;
        float f2 = pointF.y / 2.0f;
        float f3 = f * 0.55228f;
        float f4 = f2 * 0.55228f;
        path.reset();
        if (aVar.d) {
            float f5 = -f2;
            path.moveTo(DefinitionKt.NO_Float_VALUE, f5);
            float f6 = DefinitionKt.NO_Float_VALUE - f3;
            float f7 = -f;
            float f8 = DefinitionKt.NO_Float_VALUE - f4;
            path.cubicTo(f6, f5, f7, f8, f7, DefinitionKt.NO_Float_VALUE);
            float f9 = f4 + DefinitionKt.NO_Float_VALUE;
            path.cubicTo(f7, f9, f6, f2, DefinitionKt.NO_Float_VALUE, f2);
            float f10 = f3 + DefinitionKt.NO_Float_VALUE;
            path.cubicTo(f10, f2, f, f9, f, DefinitionKt.NO_Float_VALUE);
            path.cubicTo(f, f8, f10, f5, DefinitionKt.NO_Float_VALUE, f5);
        } else {
            float f11 = -f2;
            path.moveTo(DefinitionKt.NO_Float_VALUE, f11);
            float f12 = f3 + DefinitionKt.NO_Float_VALUE;
            float f13 = DefinitionKt.NO_Float_VALUE - f4;
            path.cubicTo(f12, f11, f, f13, f, DefinitionKt.NO_Float_VALUE);
            float f14 = f4 + DefinitionKt.NO_Float_VALUE;
            path.cubicTo(f, f14, f12, f2, DefinitionKt.NO_Float_VALUE, f2);
            float f15 = DefinitionKt.NO_Float_VALUE - f3;
            float f16 = -f;
            path.cubicTo(f15, f2, f16, f14, f16, DefinitionKt.NO_Float_VALUE);
            path.cubicTo(f16, f13, f15, f11, DefinitionKt.NO_Float_VALUE, f11);
        }
        PointF pointF2 = (PointF) this.e.e();
        path.offset(pointF2.x, pointF2.y);
        path.close();
        this.g.a(path);
        this.h = true;
        return path;
    }
}

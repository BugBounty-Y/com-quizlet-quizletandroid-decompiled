package com.airbnb.lottie.animation.keyframe;

import android.graphics.ColorFilter;
import android.graphics.Matrix;
import android.graphics.PointF;
import androidx.camera.camera2.internal.c0;
import com.airbnb.lottie.y;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3633h4;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Collections;

/* loaded from: classes.dex */
public final class q {
    public final /* synthetic */ int a;
    public boolean b;
    public Object c;
    public Object d;
    public Object e;
    public Object f;
    public Object g;
    public Object h;
    public Object i;
    public Object j;
    public Object k;
    public Object l;
    public Object m;
    public Object n;
    public Object o;
    public Object p;

    public q() {
        this.a = 1;
        this.e = new androidx.navigation.internal.m();
        this.f = new androidx.navigation.internal.m();
        this.g = new androidx.navigation.internal.m();
        this.h = new androidx.navigation.internal.m();
        this.i = new androidx.navigation.internal.m();
        this.j = new c0(13);
        this.k = new androidx.constraintlayout.motion.widget.n();
        this.l = new androidx.constraintlayout.motion.widget.n();
        this.m = new androidx.constraintlayout.motion.widget.n();
        this.n = new com.quizlet.data.repository.user.e();
        this.o = new com.quizlet.data.repository.user.e();
        this.p = new com.google.android.gms.internal.appset.e(10, false);
        this.b = true;
    }

    public void a(com.airbnb.lottie.model.layer.b bVar) {
        bVar.g((e) this.l);
        bVar.g((e) this.m);
        bVar.g((e) this.n);
        bVar.g((e) this.h);
        bVar.g((e) this.i);
        bVar.g((e) this.j);
        bVar.g((e) this.k);
        bVar.g((i) this.o);
        bVar.g((i) this.p);
    }

    public void b(a aVar) {
        e eVar = (e) this.l;
        if (eVar != null) {
            eVar.a(aVar);
        }
        e eVar2 = (e) this.m;
        if (eVar2 != null) {
            eVar2.a(aVar);
        }
        e eVar3 = (e) this.n;
        if (eVar3 != null) {
            eVar3.a(aVar);
        }
        e eVar4 = (e) this.h;
        if (eVar4 != null) {
            eVar4.a(aVar);
        }
        e eVar5 = (e) this.i;
        if (eVar5 != null) {
            eVar5.a(aVar);
        }
        e eVar6 = (e) this.j;
        if (eVar6 != null) {
            eVar6.a(aVar);
        }
        e eVar7 = (e) this.k;
        if (eVar7 != null) {
            eVar7.a(aVar);
        }
        i iVar = (i) this.o;
        if (iVar != null) {
            iVar.a(aVar);
        }
        i iVar2 = (i) this.p;
        if (iVar2 != null) {
            iVar2.a(aVar);
        }
    }

    public boolean c(ColorFilter colorFilter, com.quizlet.data.repository.widget.b bVar) {
        if (colorFilter == y.a) {
            e eVar = (e) this.h;
            if (eVar == null) {
                this.h = new r(bVar, new PointF());
                return true;
            }
            eVar.j(bVar);
            return true;
        }
        if (colorFilter == y.b) {
            e eVar2 = (e) this.i;
            if (eVar2 == null) {
                this.i = new r(bVar, new PointF());
                return true;
            }
            eVar2.j(bVar);
            return true;
        }
        if (colorFilter == y.c) {
            e eVar3 = (e) this.i;
            if (eVar3 instanceof o) {
                o oVar = (o) eVar3;
                com.quizlet.data.repository.widget.b bVar2 = oVar.m;
                oVar.m = bVar;
                return true;
            }
        }
        if (colorFilter == y.d) {
            e eVar4 = (e) this.i;
            if (eVar4 instanceof o) {
                o oVar2 = (o) eVar4;
                com.quizlet.data.repository.widget.b bVar3 = oVar2.n;
                oVar2.n = bVar;
                return true;
            }
        }
        if (colorFilter == y.j) {
            e eVar5 = (e) this.j;
            if (eVar5 == null) {
                this.j = new r(bVar, new com.airbnb.lottie.value.c());
                return true;
            }
            eVar5.j(bVar);
            return true;
        }
        if (colorFilter == y.k) {
            e eVar6 = (e) this.k;
            if (eVar6 == null) {
                this.k = new r(bVar, Float.valueOf(DefinitionKt.NO_Float_VALUE));
                return true;
            }
            eVar6.j(bVar);
            return true;
        }
        if (colorFilter == 3) {
            e eVar7 = (e) this.l;
            if (eVar7 == null) {
                this.l = new r(bVar, 100);
                return true;
            }
            eVar7.j(bVar);
            return true;
        }
        if (colorFilter == y.x) {
            e eVar8 = (e) this.m;
            if (eVar8 == null) {
                this.m = new r(bVar, Float.valueOf(100.0f));
                return true;
            }
            eVar8.j(bVar);
            return true;
        }
        if (colorFilter == y.y) {
            e eVar9 = (e) this.n;
            if (eVar9 == null) {
                this.n = new r(bVar, Float.valueOf(100.0f));
                return true;
            }
            eVar9.j(bVar);
            return true;
        }
        if (colorFilter == y.l) {
            if (((i) this.o) == null) {
                this.o = new i(Collections.singletonList(new com.airbnb.lottie.value.a(Float.valueOf(DefinitionKt.NO_Float_VALUE))));
            }
            ((i) this.o).j(bVar);
            return true;
        }
        if (colorFilter != y.m) {
            return false;
        }
        if (((i) this.p) == null) {
            this.p = new i(Collections.singletonList(new com.airbnb.lottie.value.a(Float.valueOf(DefinitionKt.NO_Float_VALUE))));
        }
        ((i) this.p).j(bVar);
        return true;
    }

    public void d() {
        for (int i = 0; i < 9; i++) {
            ((float[]) this.g)[i] = 0.0f;
        }
    }

    public Matrix e() {
        PointF pointF;
        com.airbnb.lottie.value.c cVar;
        PointF pointF2;
        Matrix matrix = (Matrix) this.c;
        matrix.reset();
        e eVar = (e) this.i;
        if (eVar != null && (pointF2 = (PointF) eVar.e()) != null) {
            float f = pointF2.x;
            if (f != DefinitionKt.NO_Float_VALUE || pointF2.y != DefinitionKt.NO_Float_VALUE) {
                matrix.preTranslate(f, pointF2.y);
            }
        }
        if (!this.b) {
            e eVar2 = (e) this.k;
            if (eVar2 != null) {
                float fFloatValue = eVar2 instanceof r ? ((Float) eVar2.e()).floatValue() : ((i) eVar2).l();
                if (fFloatValue != DefinitionKt.NO_Float_VALUE) {
                    matrix.preRotate(fFloatValue);
                }
            }
        } else if (eVar != null) {
            float f2 = eVar.d;
            PointF pointF3 = (PointF) eVar.e();
            float f3 = pointF3.x;
            float f4 = pointF3.y;
            eVar.i(1.0E-4f + f2);
            PointF pointF4 = (PointF) eVar.e();
            eVar.i(f2);
            matrix.preRotate((float) Math.toDegrees(Math.atan2(pointF4.y - f4, pointF4.x - f3)));
        }
        if (((i) this.o) != null) {
            float fCos = ((i) this.p) == null ? 0.0f : (float) Math.cos(Math.toRadians((-r4.l()) + 90.0f));
            float fSin = ((i) this.p) == null ? 1.0f : (float) Math.sin(Math.toRadians((-r6.l()) + 90.0f));
            float fTan = (float) Math.tan(Math.toRadians(r1.l()));
            d();
            float[] fArr = (float[]) this.g;
            fArr[0] = fCos;
            fArr[1] = fSin;
            float f5 = -fSin;
            fArr[3] = f5;
            fArr[4] = fCos;
            fArr[8] = 1.0f;
            Matrix matrix2 = (Matrix) this.d;
            matrix2.setValues(fArr);
            d();
            fArr[0] = 1.0f;
            fArr[3] = fTan;
            fArr[4] = 1.0f;
            fArr[8] = 1.0f;
            Matrix matrix3 = (Matrix) this.e;
            matrix3.setValues(fArr);
            d();
            fArr[0] = fCos;
            fArr[1] = f5;
            fArr[3] = fSin;
            fArr[4] = fCos;
            fArr[8] = 1.0f;
            Matrix matrix4 = (Matrix) this.f;
            matrix4.setValues(fArr);
            matrix3.preConcat(matrix2);
            matrix4.preConcat(matrix3);
            matrix.preConcat(matrix4);
        }
        e eVar3 = (e) this.j;
        if (eVar3 != null && (cVar = (com.airbnb.lottie.value.c) eVar3.e()) != null) {
            float f6 = cVar.a;
            if (f6 != 1.0f || cVar.b != 1.0f) {
                matrix.preScale(f6, cVar.b);
            }
        }
        e eVar4 = (e) this.h;
        if (eVar4 != null && (pointF = (PointF) eVar4.e()) != null) {
            float f7 = pointF.x;
            if (f7 != DefinitionKt.NO_Float_VALUE || pointF.y != DefinitionKt.NO_Float_VALUE) {
                matrix.preTranslate(-f7, -pointF.y);
            }
        }
        return matrix;
    }

    public Matrix f(float f) {
        e eVar = (e) this.i;
        PointF pointF = eVar == null ? null : (PointF) eVar.e();
        e eVar2 = (e) this.j;
        com.airbnb.lottie.value.c cVar = eVar2 == null ? null : (com.airbnb.lottie.value.c) eVar2.e();
        Matrix matrix = (Matrix) this.c;
        matrix.reset();
        if (pointF != null) {
            matrix.preTranslate(pointF.x * f, pointF.y * f);
        }
        if (cVar != null) {
            double d = f;
            matrix.preScale((float) Math.pow(cVar.a, d), (float) Math.pow(cVar.b, d));
        }
        e eVar3 = (e) this.k;
        if (eVar3 != null) {
            float fFloatValue = ((Float) eVar3.e()).floatValue();
            e eVar4 = (e) this.h;
            PointF pointF2 = eVar4 != null ? (PointF) eVar4.e() : null;
            float f2 = fFloatValue * f;
            float f3 = DefinitionKt.NO_Float_VALUE;
            float f4 = pointF2 == null ? 0.0f : pointF2.x;
            if (pointF2 != null) {
                f3 = pointF2.y;
            }
            matrix.preRotate(f2, f4, f3);
        }
        return matrix;
    }

    public String toString() {
        switch (this.a) {
            case 1:
                StringBuilder sb = new StringBuilder("OTBannerUIProperty{backgroundColor='");
                sb.append((String) this.c);
                sb.append("', layoutHeight='");
                sb.append((String) this.d);
                sb.append("', summaryTitleTextProperty=");
                AbstractC3633h4.a((androidx.navigation.internal.m) this.e, sb, ", iabTitleTextProperty=");
                AbstractC3633h4.a((androidx.navigation.internal.m) this.f, sb, ", summaryTitleDescriptionTextProperty=");
                AbstractC3633h4.a((androidx.navigation.internal.m) this.g, sb, ", iabTitleDescriptionTextProperty=");
                AbstractC3633h4.a((androidx.navigation.internal.m) this.h, sb, ", summaryAdditionalDescriptionTextProperty=");
                AbstractC3633h4.a((androidx.navigation.internal.m) this.i, sb, ", acceptAllButtonProperty=");
                sb.append(((androidx.constraintlayout.motion.widget.n) this.k).toString());
                sb.append(", rejectAllButtonProperty=");
                sb.append(((androidx.constraintlayout.motion.widget.n) this.l).toString());
                sb.append(", closeButtonProperty=");
                sb.append(((c0) this.j).toString());
                sb.append(", showPreferencesButtonProperty=");
                sb.append(((androidx.constraintlayout.motion.widget.n) this.m).toString());
                sb.append(", policyLinkProperty=");
                sb.append(((com.quizlet.data.repository.user.e) this.n).toString());
                sb.append(", vendorListLinkProperty=");
                sb.append(((com.quizlet.data.repository.user.e) this.o).toString());
                sb.append(", logoProperty=");
                sb.append(((com.google.android.gms.internal.appset.e) this.p).toString());
                sb.append(", applyUIProperty=");
                return android.support.v4.media.session.a.u(sb, this.b, '}');
            default:
                return super.toString();
        }
    }

    public q(com.airbnb.lottie.model.animatable.e eVar) {
        this.a = 0;
        this.c = new Matrix();
        com.airbnb.lottie.model.animatable.c cVar = eVar.a;
        this.h = cVar == null ? null : cVar.j();
        com.airbnb.lottie.model.animatable.f fVar = eVar.b;
        this.i = fVar == null ? null : fVar.j();
        com.airbnb.lottie.model.animatable.a aVar = eVar.c;
        this.j = aVar == null ? null : aVar.j();
        com.airbnb.lottie.model.animatable.b bVar = eVar.d;
        this.k = bVar == null ? null : bVar.j();
        com.airbnb.lottie.model.animatable.b bVar2 = eVar.f;
        i iVarJ = bVar2 == null ? null : bVar2.j();
        this.o = iVarJ;
        this.b = eVar.j;
        if (iVarJ != null) {
            this.d = new Matrix();
            this.e = new Matrix();
            this.f = new Matrix();
            this.g = new float[9];
        } else {
            this.d = null;
            this.e = null;
            this.f = null;
            this.g = null;
        }
        com.airbnb.lottie.model.animatable.b bVar3 = eVar.g;
        this.p = bVar3 == null ? null : bVar3.j();
        com.airbnb.lottie.model.animatable.a aVar2 = eVar.e;
        if (aVar2 != null) {
            this.l = aVar2.j();
        }
        com.airbnb.lottie.model.animatable.b bVar4 = eVar.h;
        if (bVar4 != null) {
            this.m = bVar4.j();
        } else {
            this.m = null;
        }
        com.airbnb.lottie.model.animatable.b bVar5 = eVar.i;
        if (bVar5 != null) {
            this.n = bVar5.j();
        } else {
            this.n = null;
        }
    }
}

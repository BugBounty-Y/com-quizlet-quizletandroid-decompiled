package com.airbnb.lottie.animation.content;

import android.graphics.ColorFilter;
import android.graphics.Path;
import android.graphics.PathMeasure;
import android.graphics.PointF;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.ui.graphics.vector.C0868g;
import com.airbnb.lottie.u;
import com.airbnb.lottie.y;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes.dex */
public final class n implements m, com.airbnb.lottie.animation.keyframe.a, k {
    public final String e;
    public final u f;
    public final int g;
    public final boolean h;
    public final boolean i;
    public final com.airbnb.lottie.animation.keyframe.i j;
    public final com.airbnb.lottie.animation.keyframe.e k;
    public final com.airbnb.lottie.animation.keyframe.i l;
    public final com.airbnb.lottie.animation.keyframe.i m;
    public final com.airbnb.lottie.animation.keyframe.i n;
    public final com.airbnb.lottie.animation.keyframe.i o;
    public final com.airbnb.lottie.animation.keyframe.i p;
    public boolean r;
    public final Path a = new Path();
    public final Path b = new Path();
    public final PathMeasure c = new PathMeasure();
    public final float[] d = new float[2];
    public final C0868g q = new C0868g(1);

    public n(u uVar, com.airbnb.lottie.model.layer.b bVar, com.airbnb.lottie.model.content.h hVar) {
        this.f = uVar;
        this.e = hVar.a;
        int i = hVar.b;
        this.g = i;
        this.h = hVar.j;
        this.i = hVar.k;
        com.airbnb.lottie.animation.keyframe.i iVarJ = hVar.c.j();
        this.j = iVarJ;
        com.airbnb.lottie.animation.keyframe.e eVarJ = hVar.d.j();
        this.k = eVarJ;
        com.airbnb.lottie.animation.keyframe.i iVarJ2 = hVar.e.j();
        this.l = iVarJ2;
        com.airbnb.lottie.animation.keyframe.i iVarJ3 = hVar.g.j();
        this.n = iVarJ3;
        com.airbnb.lottie.animation.keyframe.i iVarJ4 = hVar.i.j();
        this.p = iVarJ4;
        if (i == 1) {
            this.m = hVar.f.j();
            this.o = hVar.h.j();
        } else {
            this.m = null;
            this.o = null;
        }
        bVar.g(iVarJ);
        bVar.g(eVarJ);
        bVar.g(iVarJ2);
        bVar.g(iVarJ3);
        bVar.g(iVarJ4);
        if (i == 1) {
            bVar.g(this.m);
            bVar.g(this.o);
        }
        iVarJ.a(this);
        eVarJ.a(this);
        iVarJ2.a(this);
        iVarJ3.a(this);
        iVarJ4.a(this);
        if (i == 1) {
            this.m.a(this);
            this.o.a(this);
        }
    }

    @Override // com.airbnb.lottie.animation.keyframe.a
    public final void a() {
        this.r = false;
        this.f.invalidateSelf();
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
                    this.q.a.add(tVar);
                    tVar.d(this);
                }
            }
            i++;
        }
    }

    @Override // com.airbnb.lottie.model.f
    public final void d(ColorFilter colorFilter, com.quizlet.data.repository.widget.b bVar) {
        com.airbnb.lottie.animation.keyframe.i iVar;
        com.airbnb.lottie.animation.keyframe.i iVar2;
        if (colorFilter == y.r) {
            this.j.j(bVar);
            return;
        }
        if (colorFilter == y.s) {
            this.l.j(bVar);
            return;
        }
        if (colorFilter == y.i) {
            this.k.j(bVar);
            return;
        }
        if (colorFilter == y.t && (iVar2 = this.m) != null) {
            iVar2.j(bVar);
            return;
        }
        if (colorFilter == y.u) {
            this.n.j(bVar);
            return;
        }
        if (colorFilter == y.v && (iVar = this.o) != null) {
            iVar.j(bVar);
        } else if (colorFilter == y.w) {
            this.p.j(bVar);
        }
    }

    @Override // com.airbnb.lottie.model.f
    public final void e(com.airbnb.lottie.model.e eVar, int i, ArrayList arrayList, com.airbnb.lottie.model.e eVar2) {
        com.airbnb.lottie.utils.g.g(eVar, i, arrayList, eVar2, this);
    }

    @Override // com.airbnb.lottie.animation.content.c
    public final String getName() {
        return this.e;
    }

    @Override // com.airbnb.lottie.animation.content.m
    public final Path h() {
        boolean z;
        double d;
        float f;
        float f2;
        double d2;
        float fCos;
        float fSin;
        float f3;
        float f4;
        float f5;
        float f6;
        int i;
        int i2;
        double d3;
        boolean z2 = this.r;
        Path path = this.a;
        if (z2) {
            return path;
        }
        path.reset();
        if (this.h) {
            this.r = true;
            return path;
        }
        int iK = AbstractC0147y.k(this.g);
        com.airbnb.lottie.animation.keyframe.e eVar = this.k;
        float f7 = DefinitionKt.NO_Float_VALUE;
        com.airbnb.lottie.animation.keyframe.i iVar = this.n;
        com.airbnb.lottie.animation.keyframe.i iVar2 = this.p;
        com.airbnb.lottie.animation.keyframe.i iVar3 = this.l;
        com.airbnb.lottie.animation.keyframe.i iVar4 = this.j;
        if (iK == 0) {
            z = true;
            float fFloatValue = ((Float) iVar4.e()).floatValue();
            double radians = Math.toRadians((iVar3 != null ? ((Float) iVar3.e()).floatValue() : 0.0d) - 90.0d);
            double d4 = fFloatValue;
            float f8 = (float) (6.283185307179586d / d4);
            if (this.i) {
                f8 *= -1.0f;
            }
            float f9 = f8;
            float f10 = f9 / 2.0f;
            float f11 = fFloatValue - ((int) fFloatValue);
            if (f11 != DefinitionKt.NO_Float_VALUE) {
                d = d4;
                radians += (1.0f - f11) * f10;
            } else {
                d = d4;
            }
            float fFloatValue2 = ((Float) iVar.e()).floatValue();
            float fFloatValue3 = ((Float) this.m.e()).floatValue();
            com.airbnb.lottie.animation.keyframe.i iVar5 = this.o;
            float fFloatValue4 = iVar5 != null ? ((Float) iVar5.e()).floatValue() / 100.0f : 0.0f;
            float fFloatValue5 = iVar2 != null ? ((Float) iVar2.e()).floatValue() / 100.0f : 0.0f;
            if (f11 != DefinitionKt.NO_Float_VALUE) {
                float fA = android.support.v4.media.session.a.a(fFloatValue2, fFloatValue3, f11, fFloatValue3);
                double d5 = fA;
                fCos = (float) (Math.cos(radians) * d5);
                fSin = (float) (Math.sin(radians) * d5);
                path.moveTo(fCos, fSin);
                f = 2.0f;
                d2 = radians + ((f9 * f11) / 2.0f);
                f3 = fA;
                f2 = f10;
            } else {
                f = 2.0f;
                double d6 = fFloatValue2;
                float fCos2 = (float) (Math.cos(radians) * d6);
                float fSin2 = (float) (Math.sin(radians) * d6);
                path.moveTo(fCos2, fSin2);
                f2 = f10;
                d2 = radians + f2;
                fCos = fCos2;
                fSin = fSin2;
                f3 = 0.0f;
            }
            double dCeil = Math.ceil(d) * 2.0d;
            double d7 = d2;
            int i3 = 0;
            boolean z3 = false;
            while (true) {
                double d8 = i3;
                if (d8 >= dCeil) {
                    break;
                }
                float f12 = z3 ? fFloatValue2 : fFloatValue3;
                if (f3 == f7 || d8 != dCeil - 2.0d) {
                    f4 = f7;
                    f5 = f2;
                } else {
                    f4 = f7;
                    f5 = (f9 * f11) / f;
                }
                if (f3 != f7 && d8 == dCeil - 1.0d) {
                    f12 = f3;
                }
                double d9 = f12;
                float fCos3 = (float) (Math.cos(d7) * d9);
                float f13 = f9;
                float fSin3 = (float) (Math.sin(d7) * d9);
                if (fFloatValue4 == f4 && fFloatValue5 == f4) {
                    path.lineTo(fCos3, fSin3);
                    f6 = f11;
                    i = i3;
                } else {
                    f6 = f11;
                    Path path2 = path;
                    float f14 = fSin;
                    double dAtan2 = (float) (Math.atan2(fSin, fCos) - 1.5707963267948966d);
                    float fCos4 = (float) Math.cos(dAtan2);
                    float fSin4 = (float) Math.sin(dAtan2);
                    i = i3;
                    float f15 = fCos;
                    double dAtan22 = (float) (Math.atan2(fSin3, fCos3) - 1.5707963267948966d);
                    float fCos5 = (float) Math.cos(dAtan22);
                    float fSin5 = (float) Math.sin(dAtan22);
                    float f16 = z3 ? fFloatValue4 : fFloatValue5;
                    float f17 = z3 ? fFloatValue5 : fFloatValue4;
                    float f18 = (z3 ? fFloatValue3 : fFloatValue2) * f16 * 0.47829f;
                    float f19 = fCos4 * f18;
                    float f20 = f18 * fSin4;
                    float f21 = (z3 ? fFloatValue2 : fFloatValue3) * f17 * 0.47829f;
                    float f22 = fCos5 * f21;
                    float f23 = f21 * fSin5;
                    if (f11 != DefinitionKt.NO_Float_VALUE) {
                        if (i == 0) {
                            f19 *= f6;
                            f20 *= f6;
                        } else if (d8 == dCeil - 1.0d) {
                            f22 *= f6;
                            f23 *= f6;
                        }
                    }
                    path = path2;
                    path.cubicTo(f15 - f19, f14 - f20, f22 + fCos3, fSin3 + f23, fCos3, fSin3);
                }
                d7 += f5;
                z3 = !z3;
                i3 = i + 1;
                fCos = fCos3;
                fSin = fSin3;
                f11 = f6;
                f9 = f13;
                f7 = f4;
            }
            PointF pointF = (PointF) eVar.e();
            path.offset(pointF.x, pointF.y);
            path.close();
        } else if (iK != 1) {
            z = true;
        } else {
            int iFloor = (int) Math.floor(((Float) iVar4.e()).floatValue());
            double radians2 = Math.toRadians((iVar3 != null ? ((Float) iVar3.e()).floatValue() : 0.0d) - 90.0d);
            double d10 = iFloor;
            float fFloatValue6 = ((Float) iVar2.e()).floatValue() / 100.0f;
            float fFloatValue7 = ((Float) iVar.e()).floatValue();
            double d11 = fFloatValue7;
            z = true;
            float fCos6 = (float) (Math.cos(radians2) * d11);
            float fSin6 = (float) (Math.sin(radians2) * d11);
            path.moveTo(fCos6, fSin6);
            double d12 = (float) (6.283185307179586d / d10);
            double dCeil2 = Math.ceil(d10);
            double d13 = radians2 + d12;
            int i4 = 0;
            while (true) {
                double d14 = i4;
                if (d14 >= dCeil2) {
                    break;
                }
                double d15 = dCeil2;
                float fCos7 = (float) (Math.cos(d13) * d11);
                float fSin7 = (float) (Math.sin(d13) * d11);
                if (fFloatValue6 != DefinitionKt.NO_Float_VALUE) {
                    i2 = i4;
                    Path path3 = path;
                    d3 = d12;
                    double dAtan23 = (float) (Math.atan2(fSin6, fCos6) - 1.5707963267948966d);
                    float fCos8 = (float) Math.cos(dAtan23);
                    float fSin8 = (float) Math.sin(dAtan23);
                    float f24 = fCos6;
                    double dAtan24 = (float) (Math.atan2(fSin7, fCos7) - 1.5707963267948966d);
                    float f25 = fFloatValue7 * fFloatValue6 * 0.25f;
                    float f26 = fCos8 * f25;
                    float f27 = f25 * fSin8;
                    float fCos9 = ((float) Math.cos(dAtan24)) * f25;
                    float fSin9 = f25 * ((float) Math.sin(dAtan24));
                    if (d14 == d15 - 1.0d) {
                        Path path4 = this.b;
                        path4.reset();
                        path4.moveTo(f24, fSin6);
                        float f28 = f24 - f26;
                        float f29 = fSin6 - f27;
                        float f30 = fCos7 + fCos9;
                        float f31 = fSin7 + fSin9;
                        path4.cubicTo(f28, f29, f30, f31, fCos7, fSin7);
                        PathMeasure pathMeasure = this.c;
                        pathMeasure.setPath(path4, false);
                        float length = pathMeasure.getLength() * 0.9999f;
                        float[] fArr = this.d;
                        pathMeasure.getPosTan(length, fArr, null);
                        path = path3;
                        path.cubicTo(f28, f29, f30, f31, fArr[0], fArr[1]);
                        fCos6 = fCos7;
                        fSin6 = fSin7;
                    } else {
                        float f32 = fSin7 + fSin9;
                        path = path3;
                        path.cubicTo(f24 - f26, fSin6 - f27, fCos7 + fCos9, f32, fCos7, fSin7);
                        fCos6 = fCos7;
                        fSin6 = fSin7;
                    }
                } else {
                    i2 = i4;
                    d3 = d12;
                    fCos6 = fCos7;
                    fSin6 = fSin7;
                    if (d14 == d15 - 1.0d) {
                        i4 = i2 + 1;
                        d12 = d3;
                        dCeil2 = d15;
                    } else {
                        path.lineTo(fCos6, fSin6);
                    }
                }
                d13 += d3;
                i4 = i2 + 1;
                d12 = d3;
                dCeil2 = d15;
            }
            PointF pointF2 = (PointF) eVar.e();
            path.offset(pointF2.x, pointF2.y);
            path.close();
        }
        path.close();
        this.q.a(path);
        this.r = z;
        return path;
    }
}

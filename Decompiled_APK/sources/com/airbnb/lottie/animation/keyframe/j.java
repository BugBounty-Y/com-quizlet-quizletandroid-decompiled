package com.airbnb.lottie.animation.keyframe;

import android.graphics.PointF;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3532t;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.List;

/* loaded from: classes.dex */
public final class j extends k {
    public final /* synthetic */ int i;
    public final Object j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(List list, int i) {
        super(list);
        this.i = i;
        switch (i) {
            case 1:
                super(list);
                this.j = new PointF();
                break;
            case 2:
                super(list);
                this.j = new com.airbnb.lottie.value.c();
                break;
            default:
                int iMax = 0;
                for (int i2 = 0; i2 < list.size(); i2++) {
                    com.airbnb.lottie.model.content.c cVar = (com.airbnb.lottie.model.content.c) ((com.airbnb.lottie.value.a) list.get(i2)).b;
                    if (cVar != null) {
                        iMax = Math.max(iMax, cVar.b.length);
                    }
                }
                this.j = new com.airbnb.lottie.model.content.c(new float[iMax], new int[iMax]);
                break;
        }
    }

    @Override // com.airbnb.lottie.animation.keyframe.e
    public final Object f(com.airbnb.lottie.value.a aVar, float f) {
        Object obj;
        float f2;
        switch (this.i) {
            case 0:
                com.airbnb.lottie.model.content.c cVar = (com.airbnb.lottie.model.content.c) aVar.b;
                com.airbnb.lottie.model.content.c cVar2 = (com.airbnb.lottie.model.content.c) aVar.c;
                com.airbnb.lottie.model.content.c cVar3 = (com.airbnb.lottie.model.content.c) this.j;
                cVar3.getClass();
                if (cVar.equals(cVar2) || f <= DefinitionKt.NO_Float_VALUE) {
                    cVar3.a(cVar);
                } else if (f >= 1.0f) {
                    cVar3.a(cVar2);
                } else {
                    int[] iArr = cVar.b;
                    int length = iArr.length;
                    int[] iArr2 = cVar2.b;
                    if (length != iArr2.length) {
                        StringBuilder sb = new StringBuilder("Cannot interpolate between gradients. Lengths vary (");
                        sb.append(iArr.length);
                        sb.append(" vs ");
                        throw new IllegalArgumentException(android.support.v4.media.session.a.r(sb, iArr2.length, ")"));
                    }
                    int i = 0;
                    while (true) {
                        int length2 = iArr.length;
                        int[] iArr3 = cVar3.b;
                        float[] fArr = cVar3.a;
                        if (i < length2) {
                            fArr[i] = com.airbnb.lottie.utils.g.f(cVar.a[i], cVar2.a[i], f);
                            iArr3[i] = AbstractC3532t.c(iArr[i], f, iArr2[i]);
                            i++;
                        } else {
                            for (int length3 = iArr.length; length3 < fArr.length; length3++) {
                                fArr[length3] = fArr[iArr.length - 1];
                                iArr3[length3] = iArr3[iArr.length - 1];
                            }
                        }
                    }
                }
                return cVar3;
            case 1:
                return l(aVar, f, f, f);
            default:
                Object obj2 = aVar.b;
                if (obj2 == null || (obj = aVar.c) == null) {
                    throw new IllegalStateException("Missing values for keyframe.");
                }
                com.airbnb.lottie.value.c cVar4 = (com.airbnb.lottie.value.c) obj2;
                com.airbnb.lottie.value.c cVar5 = (com.airbnb.lottie.value.c) obj;
                com.quizlet.data.repository.widget.b bVar = this.e;
                if (bVar != null) {
                    f2 = f;
                    com.airbnb.lottie.value.c cVar6 = (com.airbnb.lottie.value.c) bVar.n(aVar.g, aVar.h.floatValue(), cVar4, cVar5, f2, d(), this.d);
                    if (cVar6 != null) {
                        return cVar6;
                    }
                } else {
                    f2 = f;
                }
                float f3 = com.airbnb.lottie.utils.g.f(cVar4.a, cVar5.a, f2);
                float f4 = com.airbnb.lottie.utils.g.f(cVar4.b, cVar5.b, f2);
                com.airbnb.lottie.value.c cVar7 = (com.airbnb.lottie.value.c) this.j;
                cVar7.a = f3;
                cVar7.b = f4;
                return cVar7;
        }
    }

    @Override // com.airbnb.lottie.animation.keyframe.e
    public /* bridge */ /* synthetic */ Object g(com.airbnb.lottie.value.a aVar, float f, float f2, float f3) {
        switch (this.i) {
            case 1:
                return l(aVar, f, f2, f3);
            default:
                return super.g(aVar, f, f2, f3);
        }
    }

    public PointF l(com.airbnb.lottie.value.a aVar, float f, float f2, float f3) {
        Object obj;
        Object obj2 = aVar.b;
        if (obj2 == null || (obj = aVar.c) == null) {
            throw new IllegalStateException("Missing values for keyframe.");
        }
        PointF pointF = (PointF) obj2;
        PointF pointF2 = (PointF) obj;
        com.quizlet.data.repository.widget.b bVar = this.e;
        if (bVar != null) {
            PointF pointF3 = (PointF) bVar.n(aVar.g, aVar.h.floatValue(), pointF, pointF2, f, d(), this.d);
            if (pointF3 != null) {
                return pointF3;
            }
        }
        PointF pointF4 = (PointF) this.j;
        float f4 = pointF.x;
        float fA = android.support.v4.media.session.a.a(pointF2.x, f4, f2, f4);
        float f5 = pointF.y;
        pointF4.set(fA, android.support.v4.media.session.a.a(pointF2.y, f5, f3, f5));
        return pointF4;
    }
}

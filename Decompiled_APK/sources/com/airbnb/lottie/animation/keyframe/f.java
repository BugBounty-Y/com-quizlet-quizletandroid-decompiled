package com.airbnb.lottie.animation.keyframe;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3532t;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.List;

/* loaded from: classes.dex */
public final class f extends k {
    public final /* synthetic */ int i;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ f(List list, int i) {
        super(list);
        this.i = i;
    }

    /* JADX WARN: Removed duplicated region for block: B:42:0x009a  */
    @Override // com.airbnb.lottie.animation.keyframe.e
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object f(com.airbnb.lottie.value.a r11, float r12) {
        /*
            r10 = this;
            int r0 = r10.i
            switch(r0) {
                case 0: goto Lbd;
                case 1: goto L48;
                default: goto L5;
            }
        L5:
            com.quizlet.data.repository.widget.b r1 = r10.e
            java.lang.Object r0 = r11.b
            if (r1 == 0) goto L35
            java.lang.Float r2 = r11.h
            if (r2 != 0) goto L14
            r2 = 2139095039(0x7f7fffff, float:3.4028235E38)
        L12:
            r3 = r2
            goto L19
        L14:
            float r2 = r2.floatValue()
            goto L12
        L19:
            r4 = r0
            com.airbnb.lottie.model.b r4 = (com.airbnb.lottie.model.b) r4
            java.lang.Object r0 = r11.c
            if (r0 != 0) goto L22
            r5 = r4
            goto L25
        L22:
            com.airbnb.lottie.model.b r0 = (com.airbnb.lottie.model.b) r0
            r5 = r0
        L25:
            float r7 = r10.c()
            float r8 = r10.d
            float r2 = r11.g
            r6 = r12
            java.lang.Object r11 = r1.n(r2, r3, r4, r5, r6, r7, r8)
            com.airbnb.lottie.model.b r11 = (com.airbnb.lottie.model.b) r11
            goto L47
        L35:
            r5 = r12
            r12 = 1065353216(0x3f800000, float:1.0)
            int r12 = (r5 > r12 ? 1 : (r5 == r12 ? 0 : -1))
            if (r12 != 0) goto L44
            java.lang.Object r11 = r11.c
            if (r11 != 0) goto L41
            goto L44
        L41:
            com.airbnb.lottie.model.b r11 = (com.airbnb.lottie.model.b) r11
            goto L47
        L44:
            r11 = r0
            com.airbnb.lottie.model.b r11 = (com.airbnb.lottie.model.b) r11
        L47:
            return r11
        L48:
            r5 = r12
            java.lang.Object r12 = r11.b
            if (r12 == 0) goto Lb5
            java.lang.Object r0 = r11.c
            r8 = 784923401(0x2ec8fb09, float:9.13954E-11)
            if (r0 != 0) goto L65
            int r0 = r11.k
            if (r0 != r8) goto L61
            r0 = r12
            java.lang.Integer r0 = (java.lang.Integer) r0
            int r0 = r0.intValue()
            r11.k = r0
        L61:
            int r0 = r11.k
        L63:
            r9 = r0
            goto L74
        L65:
            int r1 = r11.l
            if (r1 != r8) goto L71
            java.lang.Integer r0 = (java.lang.Integer) r0
            int r0 = r0.intValue()
            r11.l = r0
        L71:
            int r0 = r11.l
            goto L63
        L74:
            com.quizlet.data.repository.widget.b r0 = r10.e
            if (r0 == 0) goto L9a
            java.lang.Float r1 = r11.h
            float r2 = r1.floatValue()
            r3 = r12
            java.lang.Integer r3 = (java.lang.Integer) r3
            java.lang.Integer r4 = java.lang.Integer.valueOf(r9)
            float r6 = r10.d()
            float r7 = r10.d
            float r1 = r11.g
            java.lang.Object r0 = r0.n(r1, r2, r3, r4, r5, r6, r7)
            java.lang.Integer r0 = (java.lang.Integer) r0
            if (r0 == 0) goto L9a
            int r11 = r0.intValue()
            goto Lb0
        L9a:
            int r0 = r11.k
            if (r0 != r8) goto La6
            java.lang.Integer r12 = (java.lang.Integer) r12
            int r12 = r12.intValue()
            r11.k = r12
        La6:
            int r11 = r11.k
            android.graphics.PointF r12 = com.airbnb.lottie.utils.g.a
            float r12 = (float) r11
            int r9 = r9 - r11
            float r11 = (float) r9
            float r11 = r11 * r5
            float r11 = r11 + r12
            int r11 = (int) r11
        Lb0:
            java.lang.Integer r11 = java.lang.Integer.valueOf(r11)
            return r11
        Lb5:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r12 = "Missing values for keyframe."
            r11.<init>(r12)
            throw r11
        Lbd:
            r5 = r12
            int r11 = r10.l(r11, r5)
            java.lang.Integer r11 = java.lang.Integer.valueOf(r11)
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.airbnb.lottie.animation.keyframe.f.f(com.airbnb.lottie.value.a, float):java.lang.Object");
    }

    public int l(com.airbnb.lottie.value.a aVar, float f) {
        float f2;
        Float f3;
        if (aVar.b == null || aVar.c == null) {
            throw new IllegalStateException("Missing values for keyframe.");
        }
        com.quizlet.data.repository.widget.b bVar = this.e;
        Object obj = aVar.b;
        if (bVar == null || (f3 = aVar.h) == null) {
            f2 = f;
        } else {
            f2 = f;
            Integer num = (Integer) bVar.n(aVar.g, f3.floatValue(), (Integer) obj, (Integer) aVar.c, f2, d(), this.d);
            if (num != null) {
                return num.intValue();
            }
        }
        return AbstractC3532t.c(((Integer) obj).intValue(), com.airbnb.lottie.utils.g.b(f2, DefinitionKt.NO_Float_VALUE, 1.0f), ((Integer) aVar.c).intValue());
    }
}

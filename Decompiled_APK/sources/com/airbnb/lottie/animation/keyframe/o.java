package com.airbnb.lottie.animation.keyframe;

import android.graphics.PointF;
import java.util.ArrayList;
import java.util.Collections;

/* loaded from: classes.dex */
public final class o extends e {
    public final PointF i;
    public final PointF j;
    public final i k;
    public final i l;
    public com.quizlet.data.repository.widget.b m;
    public com.quizlet.data.repository.widget.b n;

    public o(i iVar, i iVar2) {
        super(Collections.EMPTY_LIST);
        this.i = new PointF();
        this.j = new PointF();
        this.k = iVar;
        this.l = iVar2;
        i(this.d);
    }

    @Override // com.airbnb.lottie.animation.keyframe.e
    public final Object e() {
        return l();
    }

    @Override // com.airbnb.lottie.animation.keyframe.e
    public final /* bridge */ /* synthetic */ Object f(com.airbnb.lottie.value.a aVar, float f) {
        return l();
    }

    @Override // com.airbnb.lottie.animation.keyframe.e
    public final void i(float f) {
        i iVar = this.k;
        iVar.i(f);
        i iVar2 = this.l;
        iVar2.i(f);
        this.i.set(((Float) iVar.e()).floatValue(), ((Float) iVar2.e()).floatValue());
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

    /* JADX WARN: Removed duplicated region for block: B:11:0x0039  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.graphics.PointF l() {
        /*
            r12 = this;
            com.quizlet.data.repository.widget.b r0 = r12.m
            r1 = 0
            if (r0 == 0) goto L39
            com.airbnb.lottie.animation.keyframe.i r0 = r12.k
            com.airbnb.lottie.animation.keyframe.b r2 = r0.c
            com.airbnb.lottie.value.a r2 = r2.b()
            if (r2 == 0) goto L39
            java.lang.Float r3 = r2.h
            com.quizlet.data.repository.widget.b r4 = r12.m
            float r5 = r2.g
            if (r3 != 0) goto L19
            r6 = r5
            goto L1e
        L19:
            float r3 = r3.floatValue()
            r6 = r3
        L1e:
            java.lang.Object r3 = r2.b
            r7 = r3
            java.lang.Float r7 = (java.lang.Float) r7
            java.lang.Object r2 = r2.c
            r8 = r2
            java.lang.Float r8 = (java.lang.Float) r8
            float r9 = r0.c()
            float r10 = r0.d()
            float r11 = r0.d
            java.lang.Object r0 = r4.n(r5, r6, r7, r8, r9, r10, r11)
            java.lang.Float r0 = (java.lang.Float) r0
            goto L3a
        L39:
            r0 = r1
        L3a:
            com.quizlet.data.repository.widget.b r2 = r12.n
            if (r2 == 0) goto L71
            com.airbnb.lottie.animation.keyframe.i r2 = r12.l
            com.airbnb.lottie.animation.keyframe.b r3 = r2.c
            com.airbnb.lottie.value.a r3 = r3.b()
            if (r3 == 0) goto L71
            java.lang.Float r1 = r3.h
            com.quizlet.data.repository.widget.b r4 = r12.n
            float r5 = r3.g
            if (r1 != 0) goto L52
            r6 = r5
            goto L57
        L52:
            float r1 = r1.floatValue()
            r6 = r1
        L57:
            java.lang.Object r1 = r3.b
            r7 = r1
            java.lang.Float r7 = (java.lang.Float) r7
            java.lang.Object r1 = r3.c
            r8 = r1
            java.lang.Float r8 = (java.lang.Float) r8
            float r9 = r2.c()
            float r10 = r2.d()
            float r11 = r2.d
            java.lang.Object r1 = r4.n(r5, r6, r7, r8, r9, r10, r11)
            java.lang.Float r1 = (java.lang.Float) r1
        L71:
            android.graphics.PointF r2 = r12.i
            android.graphics.PointF r3 = r12.j
            r4 = 0
            if (r0 != 0) goto L7e
            float r0 = r2.x
            r3.set(r0, r4)
            goto L85
        L7e:
            float r0 = r0.floatValue()
            r3.set(r0, r4)
        L85:
            if (r1 != 0) goto L8f
            float r0 = r3.x
            float r1 = r2.y
            r3.set(r0, r1)
            return r3
        L8f:
            float r0 = r3.x
            float r1 = r1.floatValue()
            r3.set(r0, r1)
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: com.airbnb.lottie.animation.keyframe.o.l():android.graphics.PointF");
    }
}

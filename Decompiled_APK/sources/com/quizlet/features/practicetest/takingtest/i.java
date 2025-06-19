package com.quizlet.features.practicetest.takingtest;

import androidx.compose.animation.C0292t;
import com.quizlet.features.practicetest.takingtest.data.C4412f;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final /* synthetic */ class i implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ C0292t b;

    public /* synthetic */ i(C0292t c0292t, int i) {
        this.a = i;
        this.b = c0292t;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        int i = this.a;
        int iIntValue = ((Integer) obj).intValue();
        switch (i) {
            case 0:
                C0292t c0292t = this.b;
                if (((C4412f) c0292t.c()).g <= ((C4412f) c0292t.a()).g) {
                    iIntValue = -iIntValue;
                }
                return Integer.valueOf(iIntValue);
            default:
                C0292t c0292t2 = this.b;
                if (((C4412f) c0292t2.c()).g > ((C4412f) c0292t2.a()).g) {
                    iIntValue = -iIntValue;
                }
                return Integer.valueOf(iIntValue);
        }
    }
}

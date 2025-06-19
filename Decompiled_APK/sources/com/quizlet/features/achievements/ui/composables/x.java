package com.quizlet.features.achievements.ui.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3327c2;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class x implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ String b;
    public final /* synthetic */ androidx.compose.ui.q c;
    public final /* synthetic */ long d;
    public final /* synthetic */ int e;

    public /* synthetic */ x(String str, long j, androidx.compose.ui.q qVar, int i, int i2) {
        this.b = str;
        this.d = j;
        this.c = qVar;
        this.e = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(1);
                androidx.compose.ui.q qVar = this.c;
                int i = this.e;
                String str = this.b;
                com.google.android.exoplayer2.drm.b.b(iH, i, this.d, (InterfaceC0806l) obj, qVar, str);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(1);
                long j = this.d;
                AbstractC3327c2.c(iH2, this.e, j, (InterfaceC0806l) obj, this.c, this.b);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ x(String str, androidx.compose.ui.q qVar, long j, int i, int i2) {
        this.b = str;
        this.c = qVar;
        this.d = j;
        this.e = i2;
    }
}

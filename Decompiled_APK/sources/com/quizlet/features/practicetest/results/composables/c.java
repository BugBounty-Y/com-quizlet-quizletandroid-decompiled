package com.quizlet.features.practicetest.results.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3359k2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3363l2;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ q c;
    public final /* synthetic */ String d;
    public final /* synthetic */ int e;
    public final /* synthetic */ int f;

    public /* synthetic */ c(String str, q qVar, String str2, int i, int i2, int i3) {
        this.a = i3;
        this.b = str;
        this.c = qVar;
        this.d = str2;
        this.e = i;
        this.f = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.e | 1);
                String str = this.d;
                int i = this.f;
                AbstractC3359k2.a(iH, i, (InterfaceC0806l) obj, this.c, this.b, str);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.e | 1);
                String str2 = this.d;
                int i2 = this.f;
                AbstractC3363l2.a(iH2, i2, (InterfaceC0806l) obj, this.c, this.b, str2);
                break;
        }
        return Unit.a;
    }
}

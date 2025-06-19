package com.quizlet.assembly.compose.pills;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3347h2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3587b6;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class f implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ String b;
    public final /* synthetic */ q c;
    public final /* synthetic */ long d;
    public final /* synthetic */ long e;
    public final /* synthetic */ int f;
    public final /* synthetic */ int g;
    public final /* synthetic */ Object h;

    public /* synthetic */ f(androidx.compose.ui.graphics.painter.b bVar, q qVar, String str, long j, long j2, int i, int i2) {
        this.h = bVar;
        this.c = qVar;
        this.b = str;
        this.d = j;
        this.e = j2;
        this.f = i;
        this.g = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.f | 1);
                long j = this.e;
                AbstractC3587b6.d((androidx.compose.ui.graphics.painter.b) this.h, this.c, this.b, this.d, j, (InterfaceC0806l) obj, iH, this.g);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.f | 1);
                String str = (String) this.h;
                AbstractC3347h2.a(this.b, this.c, this.d, this.e, str, (InterfaceC0806l) obj, iH2, this.g);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ f(String str, q qVar, long j, long j2, String str2, int i, int i2) {
        this.b = str;
        this.c = qVar;
        this.d = j;
        this.e = j2;
        this.h = str2;
        this.f = i;
        this.g = i2;
    }
}

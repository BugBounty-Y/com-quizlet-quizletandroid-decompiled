package com.quizlet.assembly.compose.toolbars;

import androidx.compose.foundation.layout.C0374a;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3343g2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3691o6;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class i implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ String b;
    public final /* synthetic */ long c;
    public final /* synthetic */ long d;
    public final /* synthetic */ q e;
    public final /* synthetic */ androidx.compose.ui.graphics.painter.b f;
    public final /* synthetic */ int g;
    public final /* synthetic */ int h;
    public final /* synthetic */ Object i;
    public final /* synthetic */ Object j;
    public final /* synthetic */ Object k;

    public /* synthetic */ i(q qVar, String str, long j, long j2, androidx.compose.ui.graphics.painter.b bVar, Function0 function0, androidx.compose.runtime.internal.d dVar, C0374a c0374a, int i, int i2) {
        this.e = qVar;
        this.b = str;
        this.c = j;
        this.d = j2;
        this.f = bVar;
        this.i = function0;
        this.j = dVar;
        this.k = c0374a;
        this.g = i;
        this.h = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.g | 1);
                C0374a c0374a = (C0374a) this.k;
                AbstractC3691o6.c(this.e, this.b, this.c, this.d, this.f, (Function0) this.i, (androidx.compose.runtime.internal.d) this.j, c0374a, (InterfaceC0806l) obj, iH, this.h);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.g | 1);
                String str = (String) this.k;
                AbstractC3343g2.a(this.b, this.c, this.d, this.e, this.f, (String) this.i, (String) this.j, str, (InterfaceC0806l) obj, iH2, this.h);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ i(String str, long j, long j2, q qVar, androidx.compose.ui.graphics.painter.b bVar, String str2, String str3, String str4, int i, int i2) {
        this.b = str;
        this.c = j;
        this.d = j2;
        this.e = qVar;
        this.f = bVar;
        this.i = str2;
        this.j = str3;
        this.k = str4;
        this.g = i;
        this.h = i2;
    }
}

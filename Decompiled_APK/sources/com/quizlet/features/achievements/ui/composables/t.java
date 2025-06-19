package com.quizlet.features.achievements.ui.composables;

import androidx.compose.foundation.layout.z0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3125d6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3293x0;
import com.google.android.gms.internal.mlkit_vision_barcode.D0;
import com.google.android.gms.internal.mlkit_vision_camera.A1;
import com.google.android.gms.internal.mlkit_vision_camera.o3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3722s6;
import com.quizlet.data.model.L1;
import com.quizlet.search.viewmodels.M;
import com.quizlet.studiablemodels.StudiableText;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class t implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;

    public /* synthetic */ t(int i, com.quizlet.assembly.compose.modals.x xVar, int i2) {
        this.a = 5;
        this.b = i;
        this.c = xVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        Integer num = (Integer) obj2;
        switch (this.a) {
            case 0:
                num.intValue();
                com.google.android.exoplayer2.drm.b.j((L1) this.c, interfaceC0806l, C0776c.H(this.b | 1));
                break;
            case 1:
                num.getClass();
                AbstractC3125d6.a((com.quizlet.features.infra.folder.menu.viewmodel.n) this.c, interfaceC0806l, C0776c.H(1), this.b);
                break;
            case 2:
                num.intValue();
                A1.b((z0) this.c, interfaceC0806l, C0776c.H(this.b | 1));
                break;
            case 3:
                num.intValue();
                o3.c((StudiableText) this.c, interfaceC0806l, C0776c.H(this.b | 1));
                break;
            case 4:
                num.intValue();
                AbstractC3722s6.a((androidx.compose.ui.graphics.painter.b) this.c, interfaceC0806l, C0776c.H(this.b | 1));
                break;
            case 5:
                num.getClass();
                AbstractC3293x0.a(this.b, (com.quizlet.assembly.compose.modals.x) this.c, interfaceC0806l, C0776c.H(65));
                break;
            default:
                num.getClass();
                D0.j((M) this.c, this.b, interfaceC0806l, C0776c.H(1));
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ t(com.quizlet.features.infra.folder.menu.viewmodel.n nVar, int i, int i2) {
        this.a = 1;
        this.c = nVar;
        this.b = i2;
    }

    public /* synthetic */ t(M m, int i, int i2) {
        this.a = 6;
        this.c = m;
        this.b = i;
    }

    public /* synthetic */ t(Object obj, int i, int i2) {
        this.a = i2;
        this.c = obj;
        this.b = i;
    }
}

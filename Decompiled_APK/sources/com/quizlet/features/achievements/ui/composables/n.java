package com.quizlet.features.achievements.ui.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3153g7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3200m0;
import com.google.android.gms.internal.mlkit_vision_barcode.H4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3502n4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3537t4;
import com.quizlet.data.model.B2;
import com.quizlet.data.model.EssayItem;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class n implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ int c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    public /* synthetic */ n(int i, B2 b2, androidx.appcompat.view.a aVar, int i2) {
        this.a = 6;
        this.b = i;
        this.d = b2;
        this.e = aVar;
        this.c = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.b | 1);
                androidx.compose.ui.q qVar = (androidx.compose.ui.q) this.e;
                com.facebook.appevents.codeless.i.a(iH, this.c, (InterfaceC0806l) obj, qVar, (String) this.d);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.b | 1);
                Function0 function0 = (Function0) this.e;
                H4.b(iH2, this.c, (InterfaceC0806l) obj, (androidx.compose.ui.n) this.d, function0);
                break;
            case 2:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(this.b | 1);
                androidx.compose.ui.q qVar2 = (androidx.compose.ui.q) this.e;
                int i = this.c;
                AbstractC3153g7.d((EssayItem) this.d, qVar2, (InterfaceC0806l) obj, iH3, i);
                break;
            case 3:
                ((Integer) obj2).intValue();
                int iH4 = C0776c.H(this.c | 1);
                AbstractC3502n4.a((androidx.camera.core.impl.utils.e) this.d, this.b, (Function0) this.e, (InterfaceC0806l) obj, iH4);
                break;
            case 4:
                ((Integer) obj2).getClass();
                int iH5 = C0776c.H(1);
                int i2 = this.c;
                androidx.compose.ui.q qVar3 = (androidx.compose.ui.q) this.e;
                AbstractC3537t4.b((androidx.compose.ui.graphics.painter.b) this.d, this.b, i2, qVar3, (InterfaceC0806l) obj, iH5);
                break;
            case 5:
                ((Integer) obj2).intValue();
                int iH6 = C0776c.H(this.c | 1);
                com.google.mlkit.common.model.a.a((androidx.compose.foundation.lazy.A) this.d, this.b, (Function2) this.e, (InterfaceC0806l) obj, iH6);
                break;
            case 6:
                ((Integer) obj2).getClass();
                int iH7 = C0776c.H(this.c | 1);
                androidx.appcompat.view.a aVar = (androidx.appcompat.view.a) this.e;
                _COROUTINE.a.c(this.b, (B2) this.d, aVar, (InterfaceC0806l) obj, iH7);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH8 = C0776c.H(this.b | 1);
                Function0 function02 = (Function0) this.d;
                int i3 = this.c;
                AbstractC3200m0.a((androidx.compose.ui.q) this.e, function02, (InterfaceC0806l) obj, iH8, i3);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ n(androidx.compose.ui.q qVar, Function0 function0, int i, int i2) {
        this.a = 7;
        this.e = qVar;
        this.d = function0;
        this.b = i;
        this.c = i2;
    }

    public /* synthetic */ n(androidx.compose.ui.graphics.painter.b bVar, int i, int i2, androidx.compose.ui.q qVar, int i3) {
        this.a = 4;
        this.d = bVar;
        this.b = i;
        this.c = i2;
        this.e = qVar;
    }

    public /* synthetic */ n(Object obj, int i, InterfaceC4938g interfaceC4938g, int i2, int i3) {
        this.a = i3;
        this.d = obj;
        this.b = i;
        this.e = interfaceC4938g;
        this.c = i2;
    }

    public /* synthetic */ n(Object obj, Object obj2, int i, int i2, int i3) {
        this.a = i3;
        this.d = obj;
        this.e = obj2;
        this.b = i;
        this.c = i2;
    }
}

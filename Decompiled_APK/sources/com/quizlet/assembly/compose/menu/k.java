package com.quizlet.assembly.compose.menu;

import androidx.compose.foundation.layout.A0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3502n4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.H5;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class k implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ int c;
    public final /* synthetic */ Function0 d;
    public final /* synthetic */ androidx.compose.ui.q e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;
    public final /* synthetic */ InterfaceC4938g h;
    public final /* synthetic */ Object i;
    public final /* synthetic */ Object j;
    public final /* synthetic */ Object k;

    public /* synthetic */ k(androidx.compose.runtime.internal.d dVar, Function0 function0, androidx.compose.ui.q qVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, boolean z, j jVar, A0 a0, androidx.compose.foundation.interaction.l lVar, int i) {
        this.f = dVar;
        this.d = function0;
        this.e = qVar;
        this.g = dVar2;
        this.h = dVar3;
        this.b = z;
        this.i = jVar;
        this.j = a0;
        this.k = lVar;
        this.c = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.c | 1);
                androidx.compose.runtime.internal.d dVar = (androidx.compose.runtime.internal.d) this.f;
                j jVar = (j) this.i;
                A0 a0 = (A0) this.j;
                androidx.compose.foundation.interaction.l lVar = (androidx.compose.foundation.interaction.l) this.k;
                H5.a(dVar, this.d, this.e, (androidx.compose.runtime.internal.d) this.g, (androidx.compose.runtime.internal.d) this.h, this.b, jVar, a0, lVar, (InterfaceC0806l) obj, iH);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(1);
                androidx.compose.ui.q qVar = this.e;
                Integer num = (Integer) this.k;
                AbstractC3502n4.b((com.quizlet.features.userprofile.data.a) this.f, this.b, (androidx.camera.core.impl.utils.e) this.g, this.c, this.d, (Function0) this.h, (Function0) this.i, (Function0) this.j, qVar, num, (InterfaceC0806l) obj, iH2);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ k(com.quizlet.features.userprofile.data.a aVar, boolean z, androidx.camera.core.impl.utils.e eVar, int i, Function0 function0, Function0 function02, Function0 function03, Function0 function04, androidx.compose.ui.q qVar, Integer num, int i2) {
        this.f = aVar;
        this.b = z;
        this.g = eVar;
        this.c = i;
        this.d = function0;
        this.h = function02;
        this.i = function03;
        this.j = function04;
        this.e = qVar;
        this.k = num;
    }
}

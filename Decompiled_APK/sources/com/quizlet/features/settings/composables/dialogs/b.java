package com.quizlet.features.settings.composables.dialogs;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3441d3;
import com.quizlet.assembly.compose.modals.x;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.features.settings.data.models.b b;
    public final /* synthetic */ x c;
    public final /* synthetic */ Function0 d;
    public final /* synthetic */ Function0 e;

    public /* synthetic */ b(com.quizlet.features.settings.data.models.b bVar, x xVar, Function0 function0, Function0 function02, int i, int i2) {
        this.a = i2;
        this.b = bVar;
        this.c = xVar;
        this.d = function0;
        this.e = function02;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(3137);
                Function0 function0 = this.d;
                Function0 function02 = this.e;
                AbstractC3441d3.a(this.b, this.c, function0, function02, (InterfaceC0806l) obj, iH);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(3137);
                Function0 function03 = this.d;
                Function0 function04 = this.e;
                com.google.android.gms.auth.api.b.a(this.b, this.c, function03, function04, (InterfaceC0806l) obj, iH2);
                break;
        }
        return Unit.a;
    }
}

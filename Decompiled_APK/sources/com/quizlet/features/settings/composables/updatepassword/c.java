package com.quizlet.features.settings.composables.updatepassword;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3501n3;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3507o3;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.features.settings.data.models.h b;
    public final /* synthetic */ com.quizlet.features.settings.data.states.h c;
    public final /* synthetic */ String d;
    public final /* synthetic */ Function1 e;
    public final /* synthetic */ String f;
    public final /* synthetic */ Function1 g;
    public final /* synthetic */ String h;
    public final /* synthetic */ Function1 i;
    public final /* synthetic */ Function0 j;
    public final /* synthetic */ Function0 k;
    public final /* synthetic */ int l;

    public /* synthetic */ c(com.quizlet.features.settings.data.models.h hVar, com.quizlet.features.settings.data.states.h hVar2, String str, Function1 function1, String str2, Function1 function12, String str3, Function1 function13, Function0 function0, Function0 function02, int i, int i2) {
        this.a = i2;
        this.b = hVar;
        this.c = hVar2;
        this.d = str;
        this.e = function1;
        this.f = str2;
        this.g = function12;
        this.h = str3;
        this.i = function13;
        this.j = function0;
        this.k = function02;
        this.l = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.l | 1);
                com.quizlet.features.settings.data.models.h hVar = this.b;
                Function0 function0 = this.j;
                Function0 function02 = this.k;
                AbstractC3501n3.a(hVar, this.c, this.d, this.e, this.f, this.g, this.h, this.i, function0, function02, (InterfaceC0806l) obj, iH);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.l | 1);
                com.quizlet.features.settings.data.models.h hVar2 = this.b;
                Function0 function03 = this.j;
                Function0 function04 = this.k;
                AbstractC3507o3.b(hVar2, this.c, this.d, this.e, this.f, this.g, this.h, this.i, function03, function04, (InterfaceC0806l) obj, iH2);
                break;
        }
        return Unit.a;
    }
}

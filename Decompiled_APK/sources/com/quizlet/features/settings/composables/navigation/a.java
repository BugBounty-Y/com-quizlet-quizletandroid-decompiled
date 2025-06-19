package com.quizlet.features.settings.composables.navigation;

import androidx.compose.runtime.InterfaceC0806l;
import androidx.navigation.C1291m;
import androidx.navigation.H;
import com.google.android.gms.internal.mlkit_vision_common.L2;
import com.google.android.gms.internal.mlkit_vision_common.Q2;
import com.google.android.gms.internal.mlkit_vision_common.R2;
import com.google.android.gms.internal.mlkit_vision_common.Y2;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements kotlin.jvm.functions.c {
    public final /* synthetic */ int a;
    public final /* synthetic */ H b;
    public final /* synthetic */ com.quizlet.features.settings.viewmodels.p c;

    public /* synthetic */ a(H h, com.quizlet.features.settings.viewmodels.p pVar, int i) {
        this.a = i;
        this.b = h;
        this.c = pVar;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        switch (this.a) {
            case 0:
                C1291m it2 = (C1291m) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(it2, "it");
                com.quizlet.features.settings.viewmodels.p pVar = this.c;
                R2.a(this.b, pVar, (InterfaceC0806l) obj2, 0);
                break;
            case 1:
                C1291m it3 = (C1291m) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(it3, "it");
                com.quizlet.features.settings.viewmodels.p pVar2 = this.c;
                Q2.a(this.b, pVar2, (InterfaceC0806l) obj2, 0);
                break;
            case 2:
                C1291m it4 = (C1291m) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(it4, "it");
                com.quizlet.features.settings.viewmodels.p pVar3 = this.c;
                Y2.b(this.b, pVar3, null, null, null, null, (InterfaceC0806l) obj2, 0);
                break;
            default:
                C1291m it5 = (C1291m) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(it5, "it");
                com.quizlet.features.settings.viewmodels.p pVar4 = this.c;
                L2.f(this.b, pVar4, null, 0, (InterfaceC0806l) obj2, 0);
                break;
        }
        return Unit.a;
    }
}

package com.quizlet.features.notes.detail.composables.magicnotesdetail;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3225o7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3234p7;
import com.google.android.gms.internal.mlkit_vision_barcode.s7;
import com.google.android.gms.internal.mlkit_vision_barcode.t7;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.notes.detail.composables.magicnotesdetail.c, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4384c implements kotlin.jvm.functions.c {
    public static final C4384c b = new C4384c(0);
    public static final C4384c c = new C4384c(1);
    public static final C4384c d = new C4384c(2);
    public static final C4384c e = new C4384c(3);
    public final /* synthetic */ int a;

    public /* synthetic */ C4384c(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        switch (this.a) {
            case 0:
                androidx.compose.animation.F AnimatedVisibility = (androidx.compose.animation.F) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(AnimatedVisibility, "$this$AnimatedVisibility");
                AbstractC3225o7.b(androidx.compose.ui.platform.N.G(androidx.compose.ui.n.b, "essayLoading"), (InterfaceC0806l) obj2, 6);
                break;
            case 1:
                androidx.compose.animation.F AnimatedVisibility2 = (androidx.compose.animation.F) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(AnimatedVisibility2, "$this$AnimatedVisibility");
                androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
                com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
                mVar.s();
                float f = com.quizlet.ui.resources.designsystem.generated.j.h;
                mVar.s();
                mVar.p();
                AbstractC3234p7.b(androidx.compose.ui.platform.N.G(AbstractC0382e.y(nVar, f, DefinitionKt.NO_Float_VALUE, f, com.quizlet.ui.resources.designsystem.generated.j.j, 2), "flashcardsLoading"), (InterfaceC0806l) obj2, 0);
                break;
            case 2:
                androidx.compose.animation.F AnimatedVisibility3 = (androidx.compose.animation.F) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(AnimatedVisibility3, "$this$AnimatedVisibility");
                androidx.compose.ui.n nVar2 = androidx.compose.ui.n.b;
                com.quizlet.themes.m.g.p();
                s7.a(androidx.compose.ui.platform.N.G(AbstractC0382e.y(nVar2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.j, 7), "outlineLoading"), (InterfaceC0806l) obj2, 0);
                break;
            default:
                androidx.compose.animation.F AnimatedVisibility4 = (androidx.compose.animation.F) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(AnimatedVisibility4, "$this$AnimatedVisibility");
                androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
                com.quizlet.themes.m.g.p();
                t7.b(androidx.compose.ui.platform.N.G(AbstractC0382e.y(nVar3, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.j, 7), "quickReferenceLoading"), (InterfaceC0806l) obj2, 0);
                break;
        }
        return Unit.a;
    }
}

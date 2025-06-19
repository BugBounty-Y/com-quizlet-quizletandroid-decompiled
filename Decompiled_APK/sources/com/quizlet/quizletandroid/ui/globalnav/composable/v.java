package com.quizlet.quizletandroid.ui.globalnav.composable;

import android.os.Bundle;
import androidx.compose.animation.C0289p;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.navigation.C1291m;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3153g7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3171i7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_camera.F1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.K4;
import com.quizlet.data.model.EnumC4164s0;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem$FreeTrial;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem$Upgrade;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem$YourLibrary;
import com.quizlet.quizletandroid.ui.library.LibraryFragment;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

/* loaded from: classes3.dex */
public final class v implements kotlin.jvm.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.ui.n b;

    public /* synthetic */ v(androidx.compose.ui.n nVar, int i) {
        this.a = i;
        this.b = nVar;
    }

    @Override // kotlin.jvm.functions.d
    public final Object invoke(Object obj, Object obj2, Object obj3, Object obj4) {
        switch (this.a) {
            case 0:
                C0289p composable = (C0289p) obj;
                C1291m it2 = (C1291m) obj2;
                InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj3;
                ((Number) obj4).intValue();
                Intrinsics.checkNotNullParameter(composable, "$this$composable");
                Intrinsics.checkNotNullParameter(it2, "it");
                String str = ((GlobalNavSuiteItem$YourLibrary) F1.c(it2, K.a(GlobalNavSuiteItem$YourLibrary.class))).c;
                if (str == null) {
                    str = "STUDY_SETS";
                }
                Bundle bundleA = AbstractC3206m6.a(new Pair("startTab", EnumC4164s0.valueOf(str)));
                C0814p c0814p = (C0814p) interfaceC0806l;
                c0814p.Y(1765406104);
                AbstractC3153g7.a(LibraryFragment.class, this.b, AbstractC3171i7.f(c0814p), bundleA, t.c, c0814p, 0);
                c0814p.p(false);
                break;
            case 1:
                C0289p composable2 = (C0289p) obj;
                C1291m it3 = (C1291m) obj2;
                ((Number) obj4).intValue();
                Intrinsics.checkNotNullParameter(composable2, "$this$composable");
                Intrinsics.checkNotNullParameter(it3, "it");
                K4.b(((GlobalNavSuiteItem$FreeTrial) F1.c(it3, K.a(GlobalNavSuiteItem$FreeTrial.class))).c, this.b, (InterfaceC0806l) obj3, 0);
                break;
            default:
                C0289p composable3 = (C0289p) obj;
                C1291m it4 = (C1291m) obj2;
                ((Number) obj4).intValue();
                Intrinsics.checkNotNullParameter(composable3, "$this$composable");
                Intrinsics.checkNotNullParameter(it4, "it");
                K4.b(((GlobalNavSuiteItem$Upgrade) F1.c(it4, K.a(GlobalNavSuiteItem$Upgrade.class))).c, this.b, (InterfaceC0806l) obj3, 0);
                break;
        }
        return Unit.a;
    }
}

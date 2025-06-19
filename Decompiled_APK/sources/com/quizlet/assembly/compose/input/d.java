package com.quizlet.assembly.compose.input;

import android.webkit.WebView;
import androidx.activity.result.ActivityResult;
import androidx.compose.foundation.text.C0486e0;
import androidx.compose.ui.graphics.S;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class d implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function0 b;

    public /* synthetic */ d(int i, Function0 function0) {
        this.a = i;
        this.b = function0;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                C0486e0 KeyboardActions = (C0486e0) obj;
                Intrinsics.checkNotNullParameter(KeyboardActions, "$this$KeyboardActions");
                this.b.invoke();
                break;
            case 1:
                C0486e0 KeyboardActions2 = (C0486e0) obj;
                Intrinsics.checkNotNullParameter(KeyboardActions2, "$this$KeyboardActions");
                this.b.invoke();
                break;
            case 2:
                C0486e0 KeyboardActions3 = (C0486e0) obj;
                Intrinsics.checkNotNullParameter(KeyboardActions3, "$this$KeyboardActions");
                this.b.invoke();
                break;
            case 3:
                C0486e0 KeyboardActions4 = (C0486e0) obj;
                Intrinsics.checkNotNullParameter(KeyboardActions4, "$this$KeyboardActions");
                this.b.invoke();
                break;
            case 4:
                C0486e0 KeyboardActions5 = (C0486e0) obj;
                Intrinsics.checkNotNullParameter(KeyboardActions5, "$this$KeyboardActions");
                this.b.invoke();
                break;
            case 5:
                C0486e0 KeyboardActions6 = (C0486e0) obj;
                Intrinsics.checkNotNullParameter(KeyboardActions6, "$this$KeyboardActions");
                this.b.invoke();
                break;
            case 6:
                coil3.compose.h it2 = (coil3.compose.h) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                if (it2 instanceof coil3.compose.e) {
                    this.b.invoke();
                }
                break;
            case 7:
                this.b.invoke();
                break;
            case 8:
                this.b.invoke();
                break;
            case 9:
                S graphicsLayer = (S) obj;
                Intrinsics.checkNotNullParameter(graphicsLayer, "$this$graphicsLayer");
                graphicsLayer.b(((Number) this.b.invoke()).floatValue());
                break;
            case 10:
                S graphicsLayer2 = (S) obj;
                Intrinsics.checkNotNullParameter(graphicsLayer2, "$this$graphicsLayer");
                graphicsLayer2.b(((Number) this.b.invoke()).floatValue());
                break;
            case 11:
                S graphicsLayer3 = (S) obj;
                Intrinsics.checkNotNullParameter(graphicsLayer3, "$this$graphicsLayer");
                graphicsLayer3.b(((Number) this.b.invoke()).floatValue());
                break;
            case 12:
                ActivityResult it3 = (ActivityResult) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                if (it3.a == -1) {
                    this.b.invoke();
                }
                break;
            case 13:
                Boolean shouldSeeAds = (Boolean) obj;
                Intrinsics.checkNotNullParameter(shouldSeeAds, "shouldSeeAds");
                if (shouldSeeAds.booleanValue()) {
                    this.b.invoke();
                }
                break;
            case 14:
                Intrinsics.checkNotNullParameter((WebView) obj, "it");
                this.b.invoke();
                break;
            default:
                androidx.compose.ui.semantics.v semantics = (androidx.compose.ui.semantics.v) obj;
                Intrinsics.checkNotNullParameter(semantics, "$this$semantics");
                androidx.compose.ui.semantics.t.g(semantics, new androidx.compose.ui.semantics.g(((Number) this.b.invoke()).floatValue(), new kotlin.ranges.f(DefinitionKt.NO_Float_VALUE, 1.0f)));
                break;
        }
        return Unit.a;
    }
}

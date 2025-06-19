package com.quizlet.search.composables;

import androidx.compose.animation.core.C0238e;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3227p0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3253s0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3301y0;
import com.google.android.gms.internal.mlkit_vision_barcode.B0;
import com.quizlet.eventlogger.features.search.SearchType;
import com.quizlet.search.viewmodels.AbstractC4797c;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class p implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ float e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;

    public /* synthetic */ p(String str, SearchType searchType, androidx.compose.ui.n nVar, float f, AbstractC4797c abstractC4797c, InterfaceC4938g interfaceC4938g, int i, int i2) {
        this.a = i2;
        this.b = str;
        this.c = searchType;
        this.d = nVar;
        this.e = f;
        this.f = abstractC4797c;
        this.g = interfaceC4938g;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                AbstractC3227p0.b((String) this.b, (SearchType) this.c, (androidx.compose.ui.n) this.d, this.e, (com.quizlet.search.viewmodels.u) this.f, (Function2) this.g, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 1:
                ((Integer) obj2).getClass();
                AbstractC3253s0.d((String) this.b, (SearchType) this.c, (androidx.compose.ui.n) this.d, this.e, (com.quizlet.search.viewmodels.x) this.f, (kotlin.jvm.functions.c) this.g, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 2:
                ((Integer) obj2).getClass();
                AbstractC3301y0.a((String) this.b, (SearchType) this.c, (androidx.compose.ui.n) this.d, this.e, (com.quizlet.search.viewmodels.D) this.f, (kotlin.jvm.functions.c) this.g, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 3:
                ((Integer) obj2).getClass();
                B0.f((String) this.b, (SearchType) this.c, (androidx.compose.ui.n) this.d, this.e, (com.quizlet.search.viewmodels.G) this.f, (Function2) this.g, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            default:
                ((androidx.compose.ui.input.pointer.n) obj).a();
                C0238e c0238e = (C0238e) this.g;
                C0238e c0238e2 = (C0238e) this.c;
                kotlinx.coroutines.E.A((kotlinx.coroutines.C) this.b, null, null, new com.quizlet.ui.compose.G(c0238e2, (androidx.compose.ui.geometry.b) obj2, c0238e, null), 3);
                float fFloatValue = ((Number) c0238e2.d()).floatValue();
                Float fValueOf = Float.valueOf(DefinitionKt.NO_Float_VALUE);
                Function1 function1 = (Function1) this.d;
                Function1 function12 = (Function1) this.f;
                float f = this.e;
                if (fFloatValue > DefinitionKt.NO_Float_VALUE) {
                    float fAbs = Math.abs(((Number) c0238e2.d()).floatValue());
                    function1.invoke(Float.valueOf(fAbs <= f ? fAbs / f : 1.0f));
                    function12.invoke(fValueOf);
                } else {
                    float fAbs2 = Math.abs(((Number) c0238e2.d()).floatValue());
                    function12.invoke(Float.valueOf(fAbs2 <= f ? fAbs2 / f : 1.0f));
                    function1.invoke(fValueOf);
                }
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ p(kotlinx.coroutines.C c, C0238e c0238e, Function1 function1, Function1 function12, C0238e c0238e2, float f) {
        this.a = 4;
        this.b = c;
        this.c = c0238e;
        this.d = function1;
        this.f = function12;
        this.g = c0238e2;
        this.e = f;
    }
}

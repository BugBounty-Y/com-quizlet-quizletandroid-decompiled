package com.quizlet.assembly.compose.cards;

import androidx.compose.runtime.InterfaceC0773a0;
import com.google.android.gms.internal.mlkit_vision_camera.T1;
import com.quizlet.search.data.term.TermSearchUiModel;
import com.quizlet.search.viewmodels.A;
import com.quizlet.search.viewmodels.D;
import com.quizlet.search.viewmodels.G;
import com.quizlet.search.viewmodels.u;
import com.quizlet.search.viewmodels.x;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.descriptors.j;
import kotlinx.serialization.internal.C5070y;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ a(int i, InterfaceC0773a0 interfaceC0773a0, Function1 function1) {
        this.a = 5;
        this.c = function1;
        this.b = i;
        this.d = interfaceC0773a0;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                ((Function2) this.c).invoke(Long.valueOf(((com.quizlet.ui.models.content.carditem.a) this.d).a), Integer.valueOf(this.b));
                return Unit.a;
            case 1:
                com.quizlet.ui.models.content.carditem.e eVar = (com.quizlet.ui.models.content.carditem.e) this.d;
                ((kotlin.jvm.functions.c) this.c).invoke(eVar.a, eVar.c, Integer.valueOf(this.b));
                return Unit.a;
            case 2:
                com.quizlet.ui.models.content.carditem.f fVar = (com.quizlet.ui.models.content.carditem.f) this.d;
                ((kotlin.jvm.functions.c) this.c).invoke(Long.valueOf(fVar.a), Integer.valueOf(this.b), Boolean.valueOf(fVar.k));
                return Unit.a;
            case 3:
                com.quizlet.ui.models.content.carditem.g gVar = (com.quizlet.ui.models.content.carditem.g) this.d;
                ((kotlin.jvm.functions.c) this.c).invoke(Long.valueOf(gVar.a), gVar.b, Integer.valueOf(this.b));
                return Unit.a;
            case 4:
                ((Function2) this.c).invoke(Long.valueOf(((com.quizlet.ui.models.content.carditem.h) this.d).a), Integer.valueOf(this.b));
                return Unit.a;
            case 5:
                ((Function1) this.c).invoke(Integer.valueOf(this.b));
                ((InterfaceC0773a0) this.d).setValue(Boolean.FALSE);
                return Unit.a;
            case 6:
                ((u) this.c).D((com.quizlet.ui.models.impressions.a) ((com.quizlet.ui.models.search.a) this.d), this.b);
                return Unit.a;
            case 7:
                ((x) this.c).D((com.quizlet.ui.models.impressions.a) ((com.quizlet.ui.models.search.a) this.d), this.b);
                return Unit.a;
            case 8:
                ((A) this.c).D((com.quizlet.ui.models.impressions.a) ((com.quizlet.ui.models.search.a) this.d), this.b);
                return Unit.a;
            case 9:
                ((D) this.c).D((com.quizlet.ui.models.impressions.a) ((com.quizlet.ui.models.search.a) this.d), this.b);
                return Unit.a;
            case 10:
                ((G) this.c).D((com.quizlet.ui.models.impressions.a) ((com.quizlet.ui.models.search.a) this.d), this.b);
                return Unit.a;
            case 11:
                ((Function2) this.c).invoke((TermSearchUiModel) this.d, Integer.valueOf(this.b));
                return Unit.a;
            default:
                int i = this.b;
                SerialDescriptor[] serialDescriptorArr = new SerialDescriptor[i];
                for (int i2 = 0; i2 < i; i2++) {
                    serialDescriptorArr[i2] = T1.g(((String) this.c) + '.' + ((C5070y) this.d).e[i2], j.e, new SerialDescriptor[0], new com.sdk.growthbook.utils.a(24));
                }
                return serialDescriptorArr;
        }
    }

    public /* synthetic */ a(int i, String str, C5070y c5070y) {
        this.a = 12;
        this.b = i;
        this.c = str;
        this.d = c5070y;
    }

    public /* synthetic */ a(Object obj, com.quizlet.ui.models.search.a aVar, int i, int i2) {
        this.a = i2;
        this.c = obj;
        this.d = aVar;
        this.b = i;
    }
}

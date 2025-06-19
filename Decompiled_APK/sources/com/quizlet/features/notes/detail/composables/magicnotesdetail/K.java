package com.quizlet.features.notes.detail.composables.magicnotesdetail;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.s7;
import com.google.android.gms.internal.mlkit_vision_barcode.t7;
import com.quizlet.data.model.EnumC4175w;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class K implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ EnumC4175w c;
    public final /* synthetic */ androidx.compose.ui.q d;
    public final /* synthetic */ Function0 e;
    public final /* synthetic */ int f;
    public final /* synthetic */ int g;

    public /* synthetic */ K(String str, EnumC4175w enumC4175w, androidx.compose.ui.q qVar, Function0 function0, int i, int i2, int i3) {
        this.a = i3;
        this.b = str;
        this.c = enumC4175w;
        this.d = qVar;
        this.e = function0;
        this.f = i;
        this.g = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.f | 1);
                Function0 function0 = this.e;
                s7.b(this.b, this.c, this.d, function0, (InterfaceC0806l) obj, iH, this.g);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.f | 1);
                Function0 function02 = this.e;
                t7.c(this.b, this.c, this.d, function02, (InterfaceC0806l) obj, iH2, this.g);
                break;
        }
        return Unit.a;
    }
}

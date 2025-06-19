package com.quizlet.features.settings.composables.dialogs;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.n;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3441d3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.U;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ n b;
    public final /* synthetic */ String c;
    public final /* synthetic */ Function0 d;
    public final /* synthetic */ Function0 e;

    public /* synthetic */ c(n nVar, String str, Function0 function0, Function0 function02, int i, int i2) {
        this.a = i2;
        this.b = nVar;
        this.c = str;
        this.d = function0;
        this.e = function02;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                AbstractC3441d3.b(C0776c.H(1), (InterfaceC0806l) obj, this.b, this.c, this.d, this.e);
                break;
            case 1:
                ((Integer) obj2).getClass();
                com.google.android.gms.auth.api.b.b(C0776c.H(1), (InterfaceC0806l) obj, this.b, this.c, this.d, this.e);
                break;
            default:
                ((Integer) obj2).getClass();
                U.a(C0776c.H(1), (InterfaceC0806l) obj, this.b, this.c, this.d, this.e);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ c(String str, Function0 function0, Function0 function02, n nVar, int i) {
        this.a = 2;
        this.c = str;
        this.d = function0;
        this.e = function02;
        this.b = nVar;
    }
}

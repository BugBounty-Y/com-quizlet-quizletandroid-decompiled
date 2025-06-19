package com.quizlet.features.infra.basestudy.ui;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_barcode.A5;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class e implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ String c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ Function0 e;
    public final /* synthetic */ Function0 f;
    public final /* synthetic */ q g;

    public /* synthetic */ e(String str, String str2, boolean z, Function0 function0, Function0 function02, q qVar, int i, int i2) {
        this.a = i2;
        this.b = str;
        this.c = str2;
        this.d = z;
        this.e = function0;
        this.f = function02;
        this.g = qVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(1);
                Function0 function0 = this.f;
                q qVar = this.g;
                A5.d(this.b, this.c, this.d, this.e, function0, qVar, (InterfaceC0806l) obj, iH);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(1);
                Function0 function02 = this.f;
                q qVar2 = this.g;
                A5.e(this.b, this.c, this.d, this.e, function02, qVar2, (InterfaceC0806l) obj, iH2);
                break;
        }
        return Unit.a;
    }
}

package com.quizlet.features.notes.detail.composables.common;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3135e7;
import com.google.android.gms.internal.mlkit_vision_camera.P1;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3509p;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3699p6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.D6;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class d implements Function2 {
    public final /* synthetic */ int a = 3;
    public final /* synthetic */ String b;
    public final /* synthetic */ Function0 c;
    public final /* synthetic */ q d;
    public final /* synthetic */ int e;

    public /* synthetic */ d(q qVar, String str, Function0 function0, int i, int i2) {
        this.d = qVar;
        this.b = str;
        this.c = function0;
        this.e = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(1);
                String str = this.b;
                AbstractC3135e7.a(iH, this.e, (InterfaceC0806l) obj, this.d, str, this.c);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(1);
                q qVar = this.d;
                P1.a(this.e, iH2, (InterfaceC0806l) obj, qVar, this.b, this.c);
                break;
            case 2:
                ((Integer) obj2).getClass();
                AbstractC3509p.a(C0776c.H(this.e | 1), (InterfaceC0806l) obj, this.d, this.b, this.c);
                break;
            case 3:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(1);
                Function0 function0 = this.c;
                AbstractC3699p6.a(iH3, this.e, (InterfaceC0806l) obj, this.d, this.b, function0);
                break;
            default:
                ((Integer) obj2).getClass();
                D6.e(C0776c.H(this.e | 1), (InterfaceC0806l) obj, this.d, this.b, this.c);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ d(q qVar, Function0 function0, String str, int i, int i2) {
        this.d = qVar;
        this.c = function0;
        this.b = str;
        this.e = i2;
    }

    public /* synthetic */ d(String str, q qVar, Function0 function0, int i) {
        this.b = str;
        this.d = qVar;
        this.c = function0;
        this.e = i;
    }

    public /* synthetic */ d(String str, Function0 function0, q qVar, int i) {
        this.b = str;
        this.c = function0;
        this.d = qVar;
        this.e = i;
    }

    public /* synthetic */ d(String str, Function0 function0, q qVar, int i, int i2) {
        this.b = str;
        this.c = function0;
        this.d = qVar;
        this.e = i;
    }
}

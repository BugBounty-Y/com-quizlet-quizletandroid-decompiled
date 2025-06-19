package com.quizlet.assembly.compose.menu;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.text.L;
import com.google.android.gms.internal.mlkit_vision_barcode.A5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.F5;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ long c;
    public final /* synthetic */ int d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;

    public /* synthetic */ a(s sVar, long j, Function0 function0, androidx.compose.ui.q qVar, androidx.compose.runtime.internal.d dVar, int i) {
        this.e = sVar;
        this.c = j;
        this.f = function0;
        this.b = qVar;
        this.g = dVar;
        this.d = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.d | 1);
                androidx.compose.runtime.internal.d dVar = (androidx.compose.runtime.internal.d) this.g;
                F5.d((s) this.e, this.c, (Function0) this.f, this.b, dVar, (InterfaceC0806l) obj, iH);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.d | 1);
                String str = (String) this.e;
                long j = this.c;
                L l = (L) this.g;
                A5.f(str, this.b, (androidx.compose.ui.text.style.i) this.f, j, l, (InterfaceC0806l) obj, iH2);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ a(String str, androidx.compose.ui.q qVar, androidx.compose.ui.text.style.i iVar, long j, L l, int i) {
        this.e = str;
        this.b = qVar;
        this.f = iVar;
        this.c = j;
        this.g = l;
        this.d = i;
    }
}

package com.quizlet.assembly.compose.links;

import androidx.compose.foundation.layout.A0;
import androidx.compose.foundation.layout.InterfaceC0390i;
import androidx.compose.material3.O3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.n;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_camera.F2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3761x5;
import com.quizlet.features.emailconfirmation.ui.composables.r;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class d implements Function2 {
    public final /* synthetic */ int a = 2;
    public final /* synthetic */ Function0 b;
    public final /* synthetic */ long c;
    public final /* synthetic */ int d;
    public final /* synthetic */ int e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ q g;
    public final /* synthetic */ Object h;
    public final /* synthetic */ Object i;
    public final /* synthetic */ Object j;

    public /* synthetic */ d(InterfaceC0390i interfaceC0390i, com.quizlet.features.infra.models.a aVar, String str, q qVar, long j, androidx.compose.runtime.internal.d dVar, Function0 function0, int i, int i2) {
        this.h = interfaceC0390i;
        this.i = aVar;
        this.f = str;
        this.g = qVar;
        this.c = j;
        this.j = dVar;
        this.b = function0;
        this.d = i;
        this.e = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.d | 1);
                Function0 function0 = this.b;
                AbstractC3761x5.a((String) this.f, this.c, this.g, (i) this.h, (A0) this.i, (c) this.j, function0, (InterfaceC0806l) obj, iH, this.e);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.d | 1);
                long j = this.c;
                com.quizlet.features.emailconfirmation.ui.composables.q.a((r) this.f, (n) this.g, (O3) this.h, this.b, (Function0) this.i, (Function0) this.j, j, (InterfaceC0806l) obj, iH2, this.e);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(this.d | 1);
                Function0 function02 = this.b;
                F2.a((InterfaceC0390i) this.h, (com.quizlet.features.infra.models.a) this.i, (String) this.f, this.g, this.c, (androidx.compose.runtime.internal.d) this.j, function02, (InterfaceC0806l) obj, iH3, this.e);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ d(r rVar, n nVar, O3 o3, Function0 function0, Function0 function02, Function0 function03, long j, int i, int i2) {
        this.f = rVar;
        this.g = nVar;
        this.h = o3;
        this.b = function0;
        this.i = function02;
        this.j = function03;
        this.c = j;
        this.d = i;
        this.e = i2;
    }

    public /* synthetic */ d(String str, long j, q qVar, i iVar, A0 a0, c cVar, Function0 function0, int i, int i2) {
        this.f = str;
        this.c = j;
        this.g = qVar;
        this.h = iVar;
        this.i = a0;
        this.j = cVar;
        this.b = function0;
        this.d = i;
        this.e = i2;
    }
}

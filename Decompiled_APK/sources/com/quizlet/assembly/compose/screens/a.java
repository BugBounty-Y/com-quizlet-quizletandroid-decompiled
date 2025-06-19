package com.quizlet.assembly.compose.screens;

import androidx.compose.foundation.layout.A0;
import androidx.compose.foundation.layout.z0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.painter.b;
import androidx.compose.ui.n;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3277v0;
import com.google.android.gms.internal.mlkit_vision_barcode.C0;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3348i;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3394t2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3611e6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y5;
import com.quizlet.assembly.compose.modals.x;
import com.quizlet.data.model.m2;
import com.quizlet.features.consent.onetrust.d;
import com.quizlet.features.folders.addtofolder.data.u;
import com.quizlet.features.infra.folder.menu.composable.k;
import com.quizlet.features.practicetest.takingtest.data.F;
import com.quizlet.features.questiontypes.fitb.g;
import com.quizlet.features.questiontypes.fitb.ui.l;
import com.quizlet.search.data.SearchFiltersStates;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlinx.collections.immutable.c;
import kotlinx.coroutines.flow.W;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ InterfaceC4938g e;
    public final /* synthetic */ int f;
    public final /* synthetic */ Object g;
    public final /* synthetic */ Object h;

    public /* synthetic */ a(n nVar, x xVar, String str, u uVar, Function1 function1, Function1 function12, int i) {
        this.a = 2;
        this.g = nVar;
        this.c = xVar;
        this.b = str;
        this.d = uVar;
        this.h = function1;
        this.e = function12;
        this.f = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.f | 1);
                String str = (String) this.d;
                Function0 function0 = (Function0) this.e;
                AbstractC3611e6.a((b) this.g, (String) this.b, (String) this.c, (q) this.h, str, function0, (InterfaceC0806l) obj, iH);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.f | 1);
                com.quizlet.features.blocks.ui.a aVar = (com.quizlet.features.blocks.ui.a) this.g;
                String str2 = (String) this.d;
                Function0 function02 = (Function0) this.e;
                S.a((String) this.b, aVar, (d) this.h, (String) this.c, str2, function02, (InterfaceC0806l) obj, iH2);
                break;
            case 2:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(this.f | 1);
                Function1 function1 = (Function1) this.h;
                Function1 function12 = (Function1) this.e;
                C0.a((n) this.g, (x) this.c, (String) this.b, (u) this.d, function1, function12, (InterfaceC0806l) obj, iH3);
                break;
            case 3:
                ((Integer) obj2).getClass();
                int iH4 = C0776c.H(this.f | 1);
                Function1 function13 = (Function1) this.d;
                Function2 function2 = (Function2) this.e;
                k.d((kotlinx.collections.immutable.b) this.g, (c) this.b, (q) this.h, (A0) this.c, function13, function2, (InterfaceC0806l) obj, iH4);
                break;
            case 4:
                ((Integer) obj2).getClass();
                int iH5 = C0776c.H(this.f | 1);
                q qVar = (q) this.h;
                z0 z0Var = (z0) this.d;
                AbstractC3348i.a((m2) this.g, (Function0) this.e, (Function0) this.b, (Function1) this.c, qVar, z0Var, (InterfaceC0806l) obj, iH5);
                break;
            case 5:
                ((Integer) obj2).getClass();
                int iH6 = C0776c.H(this.f | 1);
                F f = (F) this.g;
                Function2 function22 = (Function2) this.h;
                Function0 function03 = (Function0) this.e;
                AbstractC3394t2.e(f, (W) this.b, (W) this.c, (Function1) this.d, function22, function03, (InterfaceC0806l) obj, iH6);
                break;
            case 6:
                ((Integer) obj2).getClass();
                int iH7 = C0776c.H(this.f | 1);
                Function1 function14 = (Function1) this.c;
                Function0 function04 = (Function0) this.d;
                l.b((g) this.g, (W) this.b, (q) this.h, (Function0) this.e, function14, function04, (InterfaceC0806l) obj, iH7);
                break;
            case 7:
                ((Integer) obj2).getClass();
                int iH8 = C0776c.H(1);
                String str3 = (String) this.d;
                Y5.g((String) this.b, (String) this.c, (b) this.g, (Function0) this.e, (n) this.h, str3, (InterfaceC0806l) obj, iH8, this.f);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH9 = C0776c.H(this.f | 1);
                Function1 function15 = (Function1) this.h;
                Function1 function16 = (Function1) this.e;
                AbstractC3277v0.a((x) this.g, (SearchFiltersStates) this.b, (kotlin.jvm.functions.c) this.c, (Function1) this.d, function15, function16, (InterfaceC0806l) obj, iH9);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ a(b bVar, String str, String str2, q qVar, String str3, Function0 function0, int i) {
        this.a = 0;
        this.g = bVar;
        this.b = str;
        this.c = str2;
        this.h = qVar;
        this.d = str3;
        this.e = function0;
        this.f = i;
    }

    public /* synthetic */ a(m2 m2Var, Function0 function0, Function0 function02, Function1 function1, q qVar, z0 z0Var, int i) {
        this.a = 4;
        this.g = m2Var;
        this.e = function0;
        this.b = function02;
        this.c = function1;
        this.h = qVar;
        this.d = z0Var;
        this.f = i;
    }

    public /* synthetic */ a(g gVar, W w, q qVar, Function0 function0, Function1 function1, Function0 function02, int i) {
        this.a = 6;
        this.g = gVar;
        this.b = w;
        this.h = qVar;
        this.e = function0;
        this.c = function1;
        this.d = function02;
        this.f = i;
    }

    public /* synthetic */ a(Object obj, Object obj2, Object obj3, Function1 function1, InterfaceC4938g interfaceC4938g, InterfaceC4938g interfaceC4938g2, int i, int i2) {
        this.a = i2;
        this.g = obj;
        this.b = obj2;
        this.c = obj3;
        this.d = function1;
        this.h = interfaceC4938g;
        this.e = interfaceC4938g2;
        this.f = i;
    }

    public /* synthetic */ a(String str, com.quizlet.features.blocks.ui.a aVar, d dVar, String str2, String str3, Function0 function0, int i) {
        this.a = 1;
        this.b = str;
        this.g = aVar;
        this.h = dVar;
        this.c = str2;
        this.d = str3;
        this.e = function0;
        this.f = i;
    }

    public /* synthetic */ a(String str, String str2, b bVar, Function0 function0, n nVar, String str3, int i, int i2) {
        this.a = 7;
        this.b = str;
        this.c = str2;
        this.g = bVar;
        this.e = function0;
        this.h = nVar;
        this.d = str3;
        this.f = i2;
    }

    public /* synthetic */ a(kotlinx.collections.immutable.b bVar, c cVar, q qVar, A0 a0, Function1 function1, Function2 function2, int i) {
        this.a = 3;
        this.g = bVar;
        this.b = cVar;
        this.h = qVar;
        this.c = a0;
        this.d = function1;
        this.e = function2;
        this.f = i;
    }
}

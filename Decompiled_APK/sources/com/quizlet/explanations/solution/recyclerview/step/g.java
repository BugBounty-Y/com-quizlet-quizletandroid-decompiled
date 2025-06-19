package com.quizlet.explanations.solution.recyclerview.step;

import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.foundation.lazy.grid.A;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.n;
import androidx.compose.ui.q;
import androidx.navigation.U;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3099a7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3134e6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3233p6;
import com.google.android.gms.internal.mlkit_vision_barcode.G4;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3324c;
import com.google.android.gms.internal.mlkit_vision_camera.S1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3586b5;
import com.quizlet.features.folders.data.Q0;
import com.quizlet.features.notes.detail.composables.magicnotesdetail.p;
import com.quizlet.quizletandroid.ui.globalnav.composable.u;
import com.quizlet.quizletandroid.ui.library.C4671p;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class g implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ int c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;

    public /* synthetic */ g(C0416v0 c0416v0, Function0 function0, boolean z, int i, n nVar, int i2) {
        this.a = 7;
        this.d = c0416v0;
        this.e = function0;
        this.b = z;
        this.c = i;
        this.f = nVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.c | 1);
                com.quizlet.explanations.solution.fragments.b bVar = (com.quizlet.explanations.solution.fragments.b) this.e;
                U u = (U) this.f;
                i.c((c) this.d, this.b, bVar, u, (InterfaceC0806l) obj, iH);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.c | 1);
                boolean z = this.b;
                Function1 function1 = (Function1) this.f;
                G4.b((Q0) this.d, (q) this.e, z, function1, (InterfaceC0806l) obj, iH2);
                break;
            case 2:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(this.c | 1);
                Function0 function0 = (Function0) this.e;
                Function0 function02 = (Function0) this.f;
                AbstractC3134e6.d(this.b, (q) this.d, function0, function02, (InterfaceC0806l) obj, iH3);
                break;
            case 3:
                ((Integer) obj2).getClass();
                int iH4 = C0776c.H(1);
                boolean z2 = this.b;
                AbstractC3099a7.a((String) this.d, (androidx.compose.ui.graphics.painter.b) this.e, (q) this.f, z2, (InterfaceC0806l) obj, iH4, this.c);
                break;
            case 4:
                ((Integer) obj2).getClass();
                int iH5 = C0776c.H(this.c | 1);
                q qVar = (q) this.f;
                boolean z3 = this.b;
                AbstractC3324c.a((String) this.d, (Function1) this.e, qVar, z3, (InterfaceC0806l) obj, iH5);
                break;
            case 5:
                androidx.compose.foundation.lazy.grid.i PagingGridList = (androidx.compose.foundation.lazy.grid.i) obj;
                androidx.paging.compose.d items = (androidx.paging.compose.d) obj2;
                Intrinsics.checkNotNullParameter(PagingGridList, "$this$PagingGridList");
                Intrinsics.checkNotNullParameter(items, "items");
                int iC = items.c();
                androidx.paging.compose.a key = S1.c(items, new com.quizlet.quizletandroid.config.features.properties.d(11));
                com.quizlet.features.setpage.header.ui.g onItemViewed = new com.quizlet.features.setpage.header.ui.g(14, items, (Function1) this.e);
                C4671p c4671p = new C4671p(items, this.c, 0);
                androidx.compose.runtime.internal.d itemContent = new androidx.compose.runtime.internal.d(true, 1475868655, new u(items, this.b, (Function1) this.f));
                Intrinsics.checkNotNullParameter(PagingGridList, "<this>");
                A state = (A) this.d;
                Intrinsics.checkNotNullParameter(state, "state");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(onItemViewed, "onItemViewed");
                Intrinsics.checkNotNullParameter(itemContent, "itemContent");
                androidx.compose.foundation.lazy.grid.i.q(PagingGridList, iC, key, c4671p, new androidx.compose.runtime.internal.d(true, 841468110, new p(key, onItemViewed, state, itemContent)), 8);
                break;
            case 6:
                ((Integer) obj2).getClass();
                int iH6 = C0776c.H(this.c | 1);
                Function1 function12 = (Function1) this.f;
                boolean z4 = this.b;
                AbstractC3586b5.b((kotlinx.collections.immutable.b) this.d, (Function1) this.e, function12, z4, (InterfaceC0806l) obj, iH6);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH7 = C0776c.H(1);
                C0416v0 c0416v0 = (C0416v0) this.d;
                int i = this.c;
                n nVar = (n) this.f;
                AbstractC3233p6.a(c0416v0, (Function0) this.e, this.b, i, nVar, (InterfaceC0806l) obj, iH7);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ g(A a, Function1 function1, int i, boolean z, Function1 function12) {
        this.a = 5;
        this.d = a;
        this.e = function1;
        this.c = i;
        this.b = z;
        this.f = function12;
    }

    public /* synthetic */ g(c cVar, boolean z, com.quizlet.explanations.solution.fragments.b bVar, U u, int i) {
        this.a = 0;
        this.d = cVar;
        this.b = z;
        this.e = bVar;
        this.f = u;
        this.c = i;
    }

    public /* synthetic */ g(Q0 q0, q qVar, boolean z, Function1 function1, int i) {
        this.a = 1;
        this.d = q0;
        this.e = qVar;
        this.b = z;
        this.f = function1;
        this.c = i;
    }

    public /* synthetic */ g(Object obj, Function1 function1, Object obj2, boolean z, int i, int i2) {
        this.a = i2;
        this.d = obj;
        this.e = function1;
        this.f = obj2;
        this.b = z;
        this.c = i;
    }

    public /* synthetic */ g(String str, androidx.compose.ui.graphics.painter.b bVar, q qVar, boolean z, int i, int i2) {
        this.a = 3;
        this.d = str;
        this.e = bVar;
        this.f = qVar;
        this.b = z;
        this.c = i2;
    }

    public /* synthetic */ g(boolean z, q qVar, Function0 function0, Function0 function02, int i) {
        this.a = 2;
        this.b = z;
        this.d = qVar;
        this.e = function0;
        this.f = function02;
        this.c = i;
    }
}

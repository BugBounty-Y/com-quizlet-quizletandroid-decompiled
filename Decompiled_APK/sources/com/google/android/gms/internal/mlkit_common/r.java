package com.google.android.gms.internal.mlkit_common;

import android.content.Context;
import androidx.compose.animation.core.J0;
import com.google.android.gms.internal.mlkit_vision_barcode.F7;
import com.google.android.gms.internal.mlkit_vision_barcode.H7;
import com.google.android.gms.internal.mlkit_vision_barcode.J7;
import com.google.android.gms.internal.mlkit_vision_camera.b3;
import com.google.android.gms.internal.mlkit_vision_camera.c3;
import com.google.android.gms.internal.mlkit_vision_camera.f3;
import com.google.android.gms.internal.mlkit_vision_common.H4;
import com.google.android.gms.internal.mlkit_vision_common.J4;
import com.google.android.gms.internal.mlkit_vision_common.K4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.m7;
import com.google.android.gms.internal.mlkit_vision_document_scanner.o7;
import com.google.android.gms.internal.mlkit_vision_document_scanner.p7;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class r extends J0 {
    public final /* synthetic */ int c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ r(int i) {
        super(7);
        this.c = i;
    }

    @Override // androidx.compose.animation.core.J0
    public final Object n(Object obj) {
        switch (this.c) {
            case 0:
                com.google.mlkit.common.sdkinternal.f fVarC = com.google.mlkit.common.sdkinternal.f.c();
                Context contextB = com.google.mlkit.common.sdkinternal.f.c().b();
                ArrayList arrayList = new ArrayList();
                ((o) obj).getClass();
                u uVar = new u(10);
                com.google.android.datatransport.cct.a aVar = com.google.android.datatransport.cct.a.e;
                com.google.android.datatransport.runtime.q.b(contextB);
                com.google.android.datatransport.runtime.q.a().c(aVar);
                com.google.android.datatransport.cct.a.d.contains(new com.google.android.datatransport.c("json"));
                arrayList.add(uVar);
                return new q(fVarC.b(), (com.google.mlkit.common.sdkinternal.i) fVarC.a(com.google.mlkit.common.sdkinternal.i.class));
            case 1:
                F7 f7 = (F7) obj;
                com.google.mlkit.common.sdkinternal.f fVarC2 = com.google.mlkit.common.sdkinternal.f.c();
                return new J7(fVarC2.b(), (com.google.mlkit.common.sdkinternal.i) fVarC2.a(com.google.mlkit.common.sdkinternal.i.class), new H7(com.google.mlkit.common.sdkinternal.f.c().b(), f7), f7.a);
            case 2:
                com.google.mlkit.common.sdkinternal.f fVarC3 = com.google.mlkit.common.sdkinternal.f.c();
                return new f3(fVarC3.b(), (com.google.mlkit.common.sdkinternal.i) fVarC3.a(com.google.mlkit.common.sdkinternal.i.class), new c3(com.google.mlkit.common.sdkinternal.f.c().b(), (b3) obj));
            case 3:
                com.google.mlkit.common.sdkinternal.f fVarC4 = com.google.mlkit.common.sdkinternal.f.c();
                return new K4(fVarC4.b(), (com.google.mlkit.common.sdkinternal.i) fVarC4.a(com.google.mlkit.common.sdkinternal.i.class), new J4(com.google.mlkit.common.sdkinternal.f.c().b(), (H4) obj));
            default:
                com.google.mlkit.common.sdkinternal.f fVarC5 = com.google.mlkit.common.sdkinternal.f.c();
                return new p7(fVarC5.b(), (com.google.mlkit.common.sdkinternal.i) fVarC5.a(com.google.mlkit.common.sdkinternal.i.class), new o7(com.google.mlkit.common.sdkinternal.f.c().b(), (m7) obj));
        }
    }
}

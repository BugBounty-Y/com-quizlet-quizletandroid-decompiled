package com.google.android.gms.internal.mlkit_vision_camera;

import android.content.Context;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.AbstractC0874w;
import androidx.compose.ui.layout.C0888i;
import androidx.compose.ui.layout.InterfaceC0889j;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.comscore.streaming.ContentType;
import kotlin.jvm.functions.Function1;

/* loaded from: classes2.dex */
public abstract class r3 {
    public static final /* synthetic */ int a = 0;

    public static final void a(Object obj, String str, androidx.compose.ui.q qVar, Function1 function1, InterfaceC0889j interfaceC0889j, AbstractC0874w abstractC0874w, InterfaceC0806l interfaceC0806l, int i, int i2) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        int i3 = i << 3;
        int i4 = (i & 126) | (i3 & 7168) | (i3 & 57344) | (i3 & 458752) | (i3 & 3670016) | (i3 & 29360128) | (i3 & 234881024) | (i3 & 1879048192);
        int i5 = i4 >> 3;
        p3.a(new coil3.compose.internal.a(obj, (coil3.compose.b) c0814p.j(coil3.compose.r.a), coil3.v.a((Context) c0814p.j(AndroidCompositionLocals_androidKt.b))), str, qVar, coil3.compose.j.v, (i2 & 16) != 0 ? null : function1, androidx.compose.ui.b.e, (i2 & 64) != 0 ? C0888i.b : interfaceC0889j, (i2 & 256) != 0 ? null : abstractC0874w, c0814p, (i4 & ContentType.LONG_FORM_ON_DEMAND) | (i5 & 896) | (i5 & 7168) | (i5 & 57344) | (i5 & 458752) | (i5 & 3670016) | (i5 & 29360128) | (i5 & 234881024) | ((((i >> 27) & 14) << 27) & 1879048192), 0);
    }

    public static final void b(Object obj, String str, androidx.compose.ui.q qVar, androidx.compose.ui.graphics.painter.b bVar, androidx.compose.ui.graphics.painter.b bVar2, InterfaceC0806l interfaceC0806l, int i, int i2) {
        androidx.compose.ui.graphics.painter.b bVar3 = (i2 & 16) != 0 ? null : bVar2;
        androidx.compose.ui.i iVar = androidx.compose.ui.b.e;
        androidx.compose.ui.layout.P p = C0888i.b;
        C0814p c0814p = (C0814p) interfaceC0806l;
        int i3 = i << 3;
        int i4 = (i & 126) | (i3 & 7168) | (57344 & i3) | (i3 & 458752) | (3670016 & i3) | (29360128 & i3) | (234881024 & i3) | (i3 & 1879048192);
        int i5 = (i >> 27) & 14;
        int i6 = i4 >> 3;
        coil3.compose.internal.a aVar = new coil3.compose.internal.a(obj, (coil3.compose.b) c0814p.j(coil3.compose.r.a), coil3.v.a((Context) c0814p.j(AndroidCompositionLocals_androidKt.b)));
        int i7 = coil3.compose.internal.g.b;
        p3.a(aVar, str, qVar, (bVar == null && bVar3 == null && bVar3 == null) ? coil3.compose.j.v : new androidx.lifecycle.compose.d(bVar, bVar3, bVar3, 2), null, iVar, p, null, c0814p, (i4 & ContentType.LONG_FORM_ON_DEMAND) | (i6 & 896) | ((i5 << 15) & 458752), 0);
    }
}

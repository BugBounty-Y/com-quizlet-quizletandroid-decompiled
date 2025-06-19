package coil3;

import android.content.Context;
import androidx.lifecycle.C1247h;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3473j;
import java.util.LinkedHashMap;
import kotlin.Unit;
import kotlin.collections.K;

/* loaded from: classes.dex */
public abstract /* synthetic */ class w {
    public static u a(Context context) {
        l lVar = new l(context);
        Unit unit = Unit.a;
        androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.e eVar = x.a;
        h hVar = lVar.c;
        LinkedHashMap linkedHashMap = hVar.a;
        if (unit != null) {
            linkedHashMap.put(eVar, unit);
        } else {
            linkedHashMap.remove(eVar);
        }
        i iVar = new i(AbstractC3473j.c(hVar.a));
        coil3.request.e eVar2 = lVar.b;
        coil3.request.e eVar3 = new coil3.request.e(eVar2.a, eVar2.b, eVar2.c, eVar2.d, eVar2.e, eVar2.f, eVar2.g, eVar2.h, eVar2.i, eVar2.j, eVar2.k, eVar2.l, eVar2.m, iVar);
        kotlin.u uVarB = kotlin.l.b(new C1247h(lVar, 8));
        kotlin.u uVarB2 = kotlin.l.b(new k(0));
        K k = K.a;
        return new u(new p(lVar.a, eVar3, uVarB, uVarB2, new d(k, k, k, k, k)));
    }
}

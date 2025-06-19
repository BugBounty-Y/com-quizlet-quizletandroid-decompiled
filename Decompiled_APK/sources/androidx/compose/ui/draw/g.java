package androidx.compose.ui.draw;

import androidx.compose.ui.graphics.AbstractC0874w;
import androidx.compose.ui.graphics.F;
import androidx.compose.ui.graphics.G;
import androidx.compose.ui.graphics.V;
import androidx.compose.ui.layout.InterfaceC0889j;
import androidx.compose.ui.q;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public abstract class g {
    public static final q a(q qVar, float f) {
        return f == 1.0f ? qVar : F.q(qVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, null, true, 126971);
    }

    public static final q b(q qVar, float f, com.quizlet.shared.usecase.folderstudymaterials.d dVar) {
        boolean z;
        int i;
        if (dVar != null) {
            i = 0;
            z = true;
        } else {
            z = false;
            i = 3;
        }
        float f2 = 0;
        return ((Float.compare(f, f2) <= 0 || Float.compare(f, f2) <= 0) && !z) ? qVar : F.p(qVar, new a(f, f, i, dVar, z));
    }

    public static final q c(q qVar, V v) {
        return F.q(qVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, v, true, 124927);
    }

    public static final q d(q qVar) {
        return F.q(qVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, null, true, 126975);
    }

    public static final q e(q qVar, Function1 function1) {
        return qVar.g(new DrawBehindElement(function1));
    }

    public static final q f(q qVar, Function1 function1) {
        return qVar.g(new DrawWithCacheElement(function1));
    }

    public static final q g(q qVar, Function1 function1) {
        return qVar.g(new DrawWithContentElement(function1));
    }

    public static q h(q qVar, androidx.compose.ui.graphics.painter.b bVar, androidx.compose.ui.d dVar, InterfaceC0889j interfaceC0889j, float f, AbstractC0874w abstractC0874w, int i) {
        if ((i & 4) != 0) {
            dVar = androidx.compose.ui.b.e;
        }
        androidx.compose.ui.d dVar2 = dVar;
        if ((i & 16) != 0) {
            f = 1.0f;
        }
        float f2 = f;
        if ((i & 32) != 0) {
            abstractC0874w = null;
        }
        return qVar.g(new PainterElement(bVar, dVar2, interfaceC0889j, f2, abstractC0874w));
    }

    public static final q i(q qVar, float f) {
        return f == DefinitionKt.NO_Float_VALUE ? qVar : F.q(qVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f, null, false, 130815);
    }

    public static q j(q qVar, float f, V v, int i) {
        boolean z;
        if ((i & 2) != 0) {
            v = F.a;
        }
        V v2 = v;
        if ((i & 4) != 0) {
            z = Float.compare(f, (float) 0) > 0;
        } else {
            z = false;
        }
        long j = G.a;
        return (Float.compare(f, (float) 0) > 0 || z) ? qVar.g(new ShadowGraphicsLayerElement(f, v2, z, j, j)) : qVar;
    }
}

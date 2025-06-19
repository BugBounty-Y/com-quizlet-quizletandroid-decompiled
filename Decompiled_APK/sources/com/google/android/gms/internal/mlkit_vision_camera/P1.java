package com.google.android.gms.internal.mlkit_vision_camera;

import android.content.Context;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.LayoutWeightElement;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.navigation.compose.C1274g;
import androidx.navigation.compose.C1276i;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W4;
import com.quizlet.assembly.compose.buttons.C4076a;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import kotlin.Pair;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5048d;

/* loaded from: classes2.dex */
public abstract class P1 {
    public static final void a(int i, int i2, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, String buttonText, Function0 buttonAction) {
        int i3;
        int i4;
        int i5;
        boolean z;
        int i6;
        Intrinsics.checkNotNullParameter(buttonText, "buttonText");
        Intrinsics.checkNotNullParameter(buttonAction, "buttonAction");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1319509161);
        int i7 = i2 | (c0814p.f(buttonText) ? 4 : 2) | (c0814p.h(buttonAction) ? 32 : 16) | (c0814p.f(qVar) ? 256 : 128) | 1024;
        if ((i7 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            i6 = i;
        } else {
            c0814p.S();
            if ((i2 & 1) == 0 || c0814p.w()) {
                i3 = i7 & (-7169);
                i4 = AbstractC3205m5.g(c0814p).a;
            } else {
                c0814p.Q();
                i3 = i7 & (-7169);
                i4 = i;
            }
            c0814p.q();
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(qVar, 1.0f);
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            androidx.compose.ui.q qVarF = AbstractC0460p.f(qVarC, ((com.quizlet.themes.b) c0814p.j(b)).V0, androidx.compose.ui.graphics.F.a);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            float fQ = ((com.quizlet.themes.j) c0814p.j(com.quizlet.themes.l.a)).q();
            mVar.q();
            androidx.compose.ui.q qVarV = AbstractC0382e.v(qVarF, fQ, com.quizlet.ui.resources.designsystem.generated.j.i);
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.e, false);
            int i8 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarV);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, kE, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i8))) {
                android.support.v4.media.session.a.z(i8, c0814p, i8, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC2, c0912h4);
            Set set = androidx.compose.material3.windowsizeclass.c.b;
            C4076a c4076a = C4076a.j;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            if (i4 == 0) {
                c0814p.X(1652242303);
                androidx.compose.ui.q qVarC3 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
                int i9 = i3;
                androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.n, c0814p, 48);
                int i10 = c0814p.P;
                InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
                androidx.compose.ui.q qVarC4 = androidx.compose.ui.a.c(c0814p, qVarC3);
                c0814p.b0();
                i5 = i4;
                if (c0814p.O) {
                    c0814p.k(c0913i);
                } else {
                    c0814p.l0();
                }
                C0776c.E(c0814p, bA, c0912h);
                C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
                if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i10))) {
                    android.support.v4.media.session.a.z(i10, c0814p, i10, c0912h3);
                }
                C0776c.E(c0814p, qVarC4, c0912h4);
                Q4.b(AbstractC3106b5.d(c0814p, R.string.practice_test_paywall_limit_reached_text), androidx.compose.foundation.layout.K0.c(nVar, 1.0f), ((com.quizlet.themes.b) c0814p.j(b)).p(), 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).j, c0814p, 48, 0, 65016);
                c0814p = c0814p;
                androidx.compose.ui.q qVarC5 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
                mVar.s();
                W4.a(buttonText, AbstractC0382e.y(qVarC5, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), buttonAction, false, c4076a, null, null, null, null, false, c0814p, (i9 & 14) | ((i9 << 3) & 896), 1000);
                c0814p.p(true);
                c0814p.p(false);
                z = true;
            } else {
                int i11 = i3;
                i5 = i4;
                c0814p.X(1653200854);
                androidx.compose.ui.q qVarC6 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
                androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.g, androidx.compose.ui.b.k, c0814p, 54);
                int i12 = c0814p.P;
                InterfaceC0803j0 interfaceC0803j0L3 = c0814p.l();
                androidx.compose.ui.q qVarC7 = androidx.compose.ui.a.c(c0814p, qVarC6);
                c0814p.b0();
                if (c0814p.O) {
                    c0814p.k(c0913i);
                } else {
                    c0814p.l0();
                }
                C0776c.E(c0814p, g0B, c0912h);
                C0776c.E(c0814p, interfaceC0803j0L3, c0912h2);
                if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i12))) {
                    android.support.v4.media.session.a.z(i12, c0814p, i12, c0912h3);
                }
                C0776c.E(c0814p, qVarC7, c0912h4);
                String strD = AbstractC3106b5.d(c0814p, R.string.practice_test_paywall_limit_reached_text);
                long jP = ((com.quizlet.themes.b) c0814p.j(b)).p();
                androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).j;
                if (1.0f <= 0.0d) {
                    throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
                }
                Q4.b(strD, new LayoutWeightElement(1.0f <= Float.MAX_VALUE ? 1.0f : Float.MAX_VALUE, true), jP, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, 0, 0, 65528);
                c0814p = c0814p;
                mVar.v();
                W4.a(buttonText, AbstractC0382e.y(nVar, com.quizlet.ui.resources.designsystem.generated.j.l, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), buttonAction, false, c4076a, null, null, null, null, false, c0814p, (i11 & 14) | ((i11 << 3) & 896), 1000);
                z = true;
                c0814p.p(true);
                c0814p.p(false);
            }
            c0814p.p(z);
            i6 = i5;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.common.d(buttonText, buttonAction, qVar, i6, i2);
        }
    }

    public static final androidx.navigation.H b(Context context) {
        androidx.navigation.H h = new androidx.navigation.H(context);
        androidx.navigation.internal.j jVar = h.b;
        androidx.navigation.X x = jVar.s;
        x.a(new C1274g(x));
        jVar.s.a(new C1276i());
        jVar.s.a(new androidx.navigation.compose.s());
        return h;
    }

    public static final KSerializer c(kotlin.reflect.c rootClass, ArrayList serializers, Function0 elementClassifierIfArray) {
        KSerializer c5048d;
        KSerializer j0Var;
        Intrinsics.checkNotNullParameter(rootClass, "<this>");
        Intrinsics.checkNotNullParameter(serializers, "serializers");
        Intrinsics.checkNotNullParameter(elementClassifierIfArray, "elementClassifierIfArray");
        if (Intrinsics.b(rootClass, kotlin.jvm.internal.K.a(Collection.class)) || Intrinsics.b(rootClass, kotlin.jvm.internal.K.a(List.class)) || Intrinsics.b(rootClass, kotlin.jvm.internal.K.a(List.class)) || Intrinsics.b(rootClass, kotlin.jvm.internal.K.a(ArrayList.class))) {
            c5048d = new C5048d((KSerializer) serializers.get(0), 0);
        } else if (Intrinsics.b(rootClass, kotlin.jvm.internal.K.a(HashSet.class))) {
            c5048d = new C5048d((KSerializer) serializers.get(0), 1);
        } else if (Intrinsics.b(rootClass, kotlin.jvm.internal.K.a(Set.class)) || Intrinsics.b(rootClass, kotlin.jvm.internal.K.a(Set.class)) || Intrinsics.b(rootClass, kotlin.jvm.internal.K.a(LinkedHashSet.class))) {
            c5048d = new C5048d((KSerializer) serializers.get(0), 2);
        } else if (Intrinsics.b(rootClass, kotlin.jvm.internal.K.a(HashMap.class))) {
            c5048d = new kotlinx.serialization.internal.F((KSerializer) serializers.get(0), (KSerializer) serializers.get(1), 0);
        } else if (Intrinsics.b(rootClass, kotlin.jvm.internal.K.a(Map.class)) || Intrinsics.b(rootClass, kotlin.jvm.internal.K.a(Map.class)) || Intrinsics.b(rootClass, kotlin.jvm.internal.K.a(LinkedHashMap.class))) {
            c5048d = new kotlinx.serialization.internal.F((KSerializer) serializers.get(0), (KSerializer) serializers.get(1), 1);
        } else {
            if (Intrinsics.b(rootClass, kotlin.jvm.internal.K.a(Map.Entry.class))) {
                KSerializer keySerializer = (KSerializer) serializers.get(0);
                KSerializer valueSerializer = (KSerializer) serializers.get(1);
                Intrinsics.checkNotNullParameter(keySerializer, "keySerializer");
                Intrinsics.checkNotNullParameter(valueSerializer, "valueSerializer");
                j0Var = new kotlinx.serialization.internal.T(keySerializer, valueSerializer, 0);
            } else if (Intrinsics.b(rootClass, kotlin.jvm.internal.K.a(Pair.class))) {
                KSerializer keySerializer2 = (KSerializer) serializers.get(0);
                KSerializer valueSerializer2 = (KSerializer) serializers.get(1);
                Intrinsics.checkNotNullParameter(keySerializer2, "keySerializer");
                Intrinsics.checkNotNullParameter(valueSerializer2, "valueSerializer");
                j0Var = new kotlinx.serialization.internal.T(keySerializer2, valueSerializer2, 1);
            } else if (Intrinsics.b(rootClass, kotlin.jvm.internal.K.a(kotlin.v.class))) {
                KSerializer aSerializer = (KSerializer) serializers.get(0);
                KSerializer bSerializer = (KSerializer) serializers.get(1);
                KSerializer cSerializer = (KSerializer) serializers.get(2);
                Intrinsics.checkNotNullParameter(aSerializer, "aSerializer");
                Intrinsics.checkNotNullParameter(bSerializer, "bSerializer");
                Intrinsics.checkNotNullParameter(cSerializer, "cSerializer");
                c5048d = new kotlinx.serialization.a(aSerializer, bSerializer, cSerializer);
            } else {
                Intrinsics.checkNotNullParameter(rootClass, "rootClass");
                if (kotlin.jvm.a.b(rootClass).isArray()) {
                    Object objInvoke = elementClassifierIfArray.invoke();
                    Intrinsics.e(objInvoke, "null cannot be cast to non-null type kotlin.reflect.KClass<kotlin.Any>");
                    kotlin.reflect.c kClass = (kotlin.reflect.c) objInvoke;
                    KSerializer elementSerializer = (KSerializer) serializers.get(0);
                    Intrinsics.checkNotNullParameter(kClass, "kClass");
                    Intrinsics.checkNotNullParameter(elementSerializer, "elementSerializer");
                    j0Var = new kotlinx.serialization.internal.j0(kClass, elementSerializer);
                } else {
                    c5048d = null;
                }
            }
            c5048d = j0Var;
        }
        if (c5048d != null) {
            return c5048d;
        }
        KSerializer[] kSerializerArr = (KSerializer[]) serializers.toArray(new KSerializer[0]);
        return AbstractC5047c0.d(rootClass, (KSerializer[]) Arrays.copyOf(kSerializerArr, kSerializerArr.length));
    }

    public static final KSerializer d(androidx.camera.camera2.internal.p0 p0Var, kotlin.reflect.o type) {
        Intrinsics.checkNotNullParameter(p0Var, "<this>");
        Intrinsics.checkNotNullParameter(type, "type");
        KSerializer kSerializerH = Q1.h(p0Var, type, true);
        if (kSerializerH != null) {
            return kSerializerH;
        }
        kotlin.reflect.c cVarI = AbstractC5047c0.i(type);
        Intrinsics.checkNotNullParameter(cVarI, "<this>");
        AbstractC5047c0.j(cVarI);
        throw null;
    }

    public static final KSerializer e(C4950i c4950i) {
        Intrinsics.checkNotNullParameter(c4950i, "<this>");
        KSerializer kSerializerG = g(c4950i);
        if (kSerializerG != null) {
            return kSerializerG;
        }
        AbstractC5047c0.j(c4950i);
        throw null;
    }

    public static final KSerializer f(androidx.camera.camera2.internal.p0 p0Var, kotlin.reflect.o type) {
        Intrinsics.checkNotNullParameter(p0Var, "<this>");
        Intrinsics.checkNotNullParameter(type, "type");
        return Q1.h(p0Var, type, false);
    }

    public static final KSerializer g(kotlin.reflect.c cVar) {
        Intrinsics.checkNotNullParameter(cVar, "<this>");
        Intrinsics.checkNotNullParameter(cVar, "<this>");
        KSerializer kSerializerD = AbstractC5047c0.d(cVar, new KSerializer[0]);
        if (kSerializerD != null) {
            return kSerializerD;
        }
        kotlin.collections.builders.h hVar = kotlinx.serialization.internal.i0.a;
        Intrinsics.checkNotNullParameter(cVar, "<this>");
        return (KSerializer) kotlinx.serialization.internal.i0.a.get(cVar);
    }

    public static final ArrayList h(androidx.camera.camera2.internal.p0 p0Var, List typeArguments, boolean z) {
        Intrinsics.checkNotNullParameter(p0Var, "<this>");
        Intrinsics.checkNotNullParameter(typeArguments, "typeArguments");
        if (z) {
            ArrayList arrayList = new ArrayList(kotlin.collections.C.q(typeArguments, 10));
            Iterator it2 = typeArguments.iterator();
            while (it2.hasNext()) {
                arrayList.add(d(p0Var, (kotlin.reflect.o) it2.next()));
            }
            return arrayList;
        }
        ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(typeArguments, 10));
        Iterator it3 = typeArguments.iterator();
        while (it3.hasNext()) {
            KSerializer kSerializerF = f(p0Var, (kotlin.reflect.o) it3.next());
            if (kSerializerF == null) {
                return null;
            }
            arrayList2.add(kSerializerF);
        }
        return arrayList2;
    }
}

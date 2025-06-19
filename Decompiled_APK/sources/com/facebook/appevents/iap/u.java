package com.facebook.appevents.iap;

import android.hardware.camera2.CameraDevice;
import androidx.camera.camera2.internal.O;
import androidx.compose.foundation.layout.A;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.B;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0392j;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.N;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3249r5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y5;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.assembly.compose.modals.x;
import com.quizlet.data.model.C4114c;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5041z;

/* loaded from: classes.dex */
public abstract class u {
    public static final void a(com.quizlet.features.achievements.data.h uiState, Function1 onEvent, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i, int i2) {
        androidx.compose.ui.q qVar2;
        int i3;
        Intrinsics.checkNotNullParameter(uiState, "uiState");
        Intrinsics.checkNotNullParameter(onEvent, "onEvent");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-230360353);
        int i4 = i | (c0814p.f(uiState) ? 4 : 2) | (c0814p.h(onEvent) ? 32 : 16);
        int i5 = i2 & 4;
        if (i5 != 0) {
            i3 = i4 | 384;
            qVar2 = qVar;
        } else {
            qVar2 = qVar;
            i3 = i4 | (c0814p.f(qVar2) ? 256 : 128);
        }
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVar3 = i5 != 0 ? androidx.compose.ui.n.b : qVar2;
            x xVarH = Y5.h(true, false, c0814p, 6, 6);
            c0814p.X(610464354);
            Object objI = c0814p.I();
            Object obj = C0804k.a;
            if (objI == obj) {
                objI = C0776c.z(null);
                c0814p.i0(objI);
            }
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objI;
            c0814p.p(false);
            c0814p.X(610466722);
            boolean zH = ((i3 & 14) == 4) | c0814p.h(xVarH);
            Object objI2 = c0814p.I();
            if (zH || objI2 == obj) {
                objI2 = new com.quizlet.features.achievements.ui.composables.o(uiState, xVarH, interfaceC0773a0, null);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            C0776c.f(c0814p, uiState, (Function2) objI2);
            if (uiState instanceof com.quizlet.features.achievements.data.e) {
                c0814p.X(1744828569);
                com.quizlet.features.achievements.data.e eVar = (com.quizlet.features.achievements.data.e) uiState;
                androidx.compose.ui.q qVarG = N.G(qVar3, "achievements_content");
                c0814p.X(610476764);
                boolean zH2 = c0814p.h(xVarH) | ((i3 & ContentType.LONG_FORM_ON_DEMAND) == 32);
                Object objI3 = c0814p.I();
                if (zH2 || objI3 == obj) {
                    objI3 = new androidx.lifecycle.compose.d(xVarH, onEvent, interfaceC0773a0, 7);
                    c0814p.i0(objI3);
                }
                c0814p.p(false);
                b(eVar, qVarG, (Function1) objI3, c0814p, 0);
                c0814p.p(false);
            } else if (Intrinsics.b(uiState, com.quizlet.features.achievements.data.f.a)) {
                c0814p.X(610486666);
                AbstractC3249r5.a(null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g(), c0814p, 0, 1);
                c0814p.p(false);
            } else {
                if (!Intrinsics.b(uiState, com.quizlet.features.achievements.data.g.a)) {
                    throw Z.j(610472638, c0814p, false);
                }
                c0814p.X(610490364);
                c0814p.X(610492243);
                boolean z = (i3 & ContentType.LONG_FORM_ON_DEMAND) == 32;
                Object objI4 = c0814p.I();
                if (z || objI4 == obj) {
                    objI4 = new com.quizlet.facebook.a(1, onEvent);
                    c0814p.i0(objI4);
                }
                c0814p.p(false);
                com.fasterxml.uuid.b.a((i3 >> 3) & ContentType.LONG_FORM_ON_DEMAND, c0814p, qVar3, (Function0) objI4);
                c0814p.p(false);
            }
            C4114c c4114c = (C4114c) interfaceC0773a0.getValue();
            if (c4114c != null) {
                com.bumptech.glide.c.a(xVarH, c4114c, null, c0814p, 8);
            }
            qVar2 = qVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.u(i, i2, 7, uiState, onEvent, qVar2);
        }
    }

    public static final void b(com.quizlet.features.achievements.data.e eVar, androidx.compose.ui.q qVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-815966577);
        int i2 = i | (c0814p.h(eVar) ? 4 : 2) | (c0814p.f(qVar) ? 32 : 16) | (c0814p.h(function1) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            C0380d c0380d = AbstractC0398m.a;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            C0392j c0392jG = AbstractC0398m.g(f);
            mVar.s();
            androidx.compose.ui.q qVarG = N.G(AbstractC0382e.u(qVar, f), "achievements_content");
            B bA = A.a(c0392jG, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarG);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            int i4 = i2 & 896;
            com.google.android.exoplayer2.drm.b.a(eVar.a, null, function1, c0814p, i4);
            c0814p.X(-748560844);
            kotlinx.collections.immutable.b bVar = eVar.b;
            if (!bVar.isEmpty()) {
                AbstractC3053s1.a(bVar, null, function1, c0814p, i4);
            }
            c0814p.p(false);
            c0814p.X(-748554890);
            if (!eVar.c.isEmpty() || !eVar.d.isEmpty()) {
                com.google.android.gms.dynamite.d.a(eVar.c, eVar.d, null, function1, c0814p, (i2 << 3) & 7168);
            }
            c0814p.p(false);
            c0814p.X(-748547834);
            if (!eVar.e.isEmpty() || !eVar.f.isEmpty() || !eVar.g.isEmpty()) {
                com.facebook.appevents.ml.f.a(eVar.e, eVar.f, eVar.g, null, function1, c0814p, (i2 << 6) & 57344);
                c0814p = c0814p;
            }
            c0814p.p(false);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.lifecycle.compose.e(i, 13, eVar, qVar, function1);
        }
    }

    public static CameraDevice.StateCallback c(ArrayList arrayList) {
        return arrayList.isEmpty() ? new O() : arrayList.size() == 1 ? (CameraDevice.StateCallback) arrayList.get(0) : new androidx.camera.camera2.internal.N(arrayList);
    }

    public static final androidx.compose.ui.text.font.o d() {
        return new androidx.compose.ui.text.font.o(C5041z.a, 11);
    }

    public static final Class e(String className) {
        if (!com.facebook.internal.instrument.crashshield.a.b(u.class)) {
            try {
                Intrinsics.checkNotNullParameter(className, "className");
                try {
                    return Class.forName(className);
                } catch (ClassNotFoundException unused) {
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(u.class, th);
                return null;
            }
        }
        return null;
    }

    public static final Method f(Class clazz, String methodName, Class... args) {
        if (!com.facebook.internal.instrument.crashshield.a.b(u.class)) {
            try {
                Intrinsics.checkNotNullParameter(clazz, "clazz");
                Intrinsics.checkNotNullParameter(methodName, "methodName");
                Intrinsics.checkNotNullParameter(args, "args");
                try {
                    return clazz.getDeclaredMethod(methodName, (Class[]) Arrays.copyOf(args, args.length));
                } catch (NoSuchMethodException unused) {
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(u.class, th);
                return null;
            }
        }
        return null;
    }

    public static final Method g(Class clazz, String methodName, Class... args) {
        if (!com.facebook.internal.instrument.crashshield.a.b(u.class)) {
            try {
                Intrinsics.checkNotNullParameter(clazz, "clazz");
                Intrinsics.checkNotNullParameter(methodName, "methodName");
                Intrinsics.checkNotNullParameter(args, "args");
                try {
                    return clazz.getMethod(methodName, (Class[]) Arrays.copyOf(args, args.length));
                } catch (NoSuchMethodException unused) {
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(u.class, th);
                return null;
            }
        }
        return null;
    }

    public static final Object h(Class clazz, Object obj, Method method, Object... args) {
        if (com.facebook.internal.instrument.crashshield.a.b(u.class)) {
            return null;
        }
        try {
            Intrinsics.checkNotNullParameter(clazz, "clazz");
            Intrinsics.checkNotNullParameter(method, "method");
            Intrinsics.checkNotNullParameter(args, "args");
            if (obj != null) {
                obj = clazz.cast(obj);
            }
            try {
                return method.invoke(obj, Arrays.copyOf(args, args.length));
            } catch (IllegalAccessException | InvocationTargetException unused) {
                return null;
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(u.class, th);
            return null;
        }
    }
}

package androidx.navigation.serialization;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.ui.node.B;
import androidx.navigation.S;
import com.google.android.gms.internal.mlkit_vision_camera.P1;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.text.D;
import kotlin.text.Regex;
import kotlin.text.StringsKt;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;

/* loaded from: classes.dex */
public abstract class d {
    public static final l a;
    public static final l b;
    public static final l c;
    public static final l d;
    public static final l e;
    public static final l f;
    public static final l g;
    public static final c h;
    public static final c i;
    public static final c j;
    public static final c k;

    static {
        boolean z = true;
        a = new l(z, 5);
        b = new l(z, 1);
        boolean z2 = false;
        c = new l(z2, 3);
        d = new l(z, 2);
        e = new l(z, 4);
        f = new l(z, 6);
        g = new l(z2, 7);
        h = new c(z, 2);
        i = new c(z, 3);
        j = new c(z, 0);
        k = new c(z, 1);
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:18:0x0080  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final androidx.navigation.S a(kotlinx.serialization.descriptors.SerialDescriptor r7, kotlin.collections.L r8) throws java.lang.ClassNotFoundException {
        /*
            Method dump skipped, instructions count: 414
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.navigation.serialization.d.a(kotlinx.serialization.descriptors.SerialDescriptor, kotlin.collections.L):androidx.navigation.S");
    }

    public static final int b(KSerializer kSerializer) {
        Intrinsics.checkNotNullParameter(kSerializer, "<this>");
        int iHashCode = kSerializer.getDescriptor().a().hashCode();
        int iF = kSerializer.getDescriptor().f();
        for (int i2 = 0; i2 < iF; i2++) {
            iHashCode = (iHashCode * 31) + kSerializer.getDescriptor().g(i2).hashCode();
        }
        return iHashCode;
    }

    public static final String c(com.quizlet.quizletandroid.ui.globalnav.data.k value, LinkedHashMap typeMap) {
        Intrinsics.checkNotNullParameter(value, "route");
        Intrinsics.checkNotNullParameter(typeMap, "typeMap");
        KSerializer serializer = P1.e(K.a(value.getClass()));
        h hVar = new h(serializer, typeMap);
        Intrinsics.checkNotNullParameter(value, "value");
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        serializer.serialize(hVar, value);
        Map mapL = V.l(hVar.d);
        com.quizlet.data.repository.progress.b bVar = new com.quizlet.data.repository.progress.b(serializer);
        j jVar = new j(0, mapL, bVar);
        int iF = serializer.getDescriptor().f();
        for (int i2 = 0; i2 < iF; i2++) {
            String strG = serializer.getDescriptor().g(i2);
            S s = (S) typeMap.get(strG);
            if (s == null) {
                throw new IllegalStateException(B.h("Cannot locate NavType for argument [", strG, ']').toString());
            }
            jVar.invoke(Integer.valueOf(i2), strG, s);
        }
        return ((String) bVar.b) + ((String) bVar.c) + ((String) bVar.d);
    }

    public static final Class d(SerialDescriptor serialDescriptor) throws ClassNotFoundException {
        String strO = D.o(serialDescriptor.a(), "?", "", false);
        try {
            Class<?> cls = Class.forName(strO);
            Intrinsics.checkNotNullExpressionValue(cls, "forName(...)");
            return cls;
        } catch (ClassNotFoundException unused) {
            if (StringsKt.G(strO, ".", false)) {
                Class<?> cls2 = Class.forName(new Regex("(\\.+)(?!.*\\.)").replace(strO, "\\$"));
                Intrinsics.checkNotNullExpressionValue(cls2, "forName(...)");
                return cls2;
            }
            String strK = "Cannot find class with name \"" + serialDescriptor.a() + "\". Ensure that the serialName for this argument is the default fully qualified name";
            if (serialDescriptor.e() instanceof kotlinx.serialization.descriptors.i) {
                strK = android.support.v4.media.session.a.k(strK, ".\nIf the build is minified, try annotating the Enum class with \"androidx.annotation.Keep\" to ensure the Enum is not removed.");
            }
            throw new IllegalArgumentException(strK);
        }
    }

    public static final boolean e(SerialDescriptor serialDescriptor) {
        Intrinsics.checkNotNullParameter(serialDescriptor, "<this>");
        return Intrinsics.b(serialDescriptor.e(), kotlinx.serialization.descriptors.j.b) && serialDescriptor.isInline() && serialDescriptor.f() == 1;
    }

    public static final e f(SerialDescriptor serialDescriptor) {
        String strO = D.o(serialDescriptor.a(), "?", "", false);
        return Intrinsics.b(serialDescriptor.e(), kotlinx.serialization.descriptors.i.b) ? serialDescriptor.c() ? e.u : e.t : Intrinsics.b(strO, "kotlin.Int") ? serialDescriptor.c() ? e.b : e.a : Intrinsics.b(strO, "kotlin.Boolean") ? serialDescriptor.c() ? e.d : e.c : Intrinsics.b(strO, "kotlin.Double") ? serialDescriptor.c() ? e.f : e.e : Intrinsics.b(strO, "kotlin.Float") ? serialDescriptor.c() ? e.h : e.g : Intrinsics.b(strO, "kotlin.Long") ? serialDescriptor.c() ? e.j : e.i : Intrinsics.b(strO, "kotlin.String") ? serialDescriptor.c() ? e.l : e.k : Intrinsics.b(strO, "kotlin.IntArray") ? e.m : Intrinsics.b(strO, "kotlin.DoubleArray") ? e.o : Intrinsics.b(strO, "kotlin.BooleanArray") ? e.n : Intrinsics.b(strO, "kotlin.FloatArray") ? e.p : Intrinsics.b(strO, "kotlin.LongArray") ? e.q : Intrinsics.b(strO, "kotlin.Array") ? e.r : D.r(strO, "kotlin.collections.ArrayList", false) ? e.s : e.v;
    }

    public static final String g(String str, String str2, String str3, String str4) {
        return AbstractC0147y.g(AbstractC0147y.h("Route ", str3, " could not find any NavType for argument ", str, " of type "), str2, " - typeMap received was ", str4);
    }
}

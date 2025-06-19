package com.google.android.gms.dynamite;

import android.media.ImageReader;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import androidx.compose.ui.n;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3223o5;
import com.google.android.gms.internal.mlkit_vision_barcode.L4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.R4;
import com.quizlet.assembly.compose.menu.i;
import com.quizlet.features.achievements.ui.composables.G;
import com.quizlet.quizletandroid.k;
import com.quizlet.themes.m;
import com.quizlet.ui.resources.designsystem.generated.j;
import io.reactivex.rxjava3.core.p;
import java.util.Set;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class d {
    public static ClassLoader a;
    public static Thread b;

    public static final void a(kotlinx.collections.immutable.b daily, kotlinx.collections.immutable.b weekly, n nVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        n nVar2;
        Intrinsics.checkNotNullParameter(daily, "daily");
        Intrinsics.checkNotNullParameter(weekly, "weekly");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1547188537);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(daily) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(weekly) ? 32 : 16;
        }
        int i3 = i2 | 384;
        if ((i & 3072) == 0) {
            i3 |= c0814p.h(function1) ? 2048 : 1024;
        }
        int i4 = i3;
        if ((i4 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            n nVar3 = n.b;
            V v = C0804k.a;
            Object[] objArr = new Object[0];
            c0814p.X(-283274817);
            Object objI = c0814p.I();
            if (objI == v) {
                objI = new com.quizlet.db.data.models.persisted.types.a(24);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) L4.d(objArr, null, (Function0) objI, c0814p, 3072, 6);
            Object[] objArr2 = new Object[0];
            c0814p.X(-283272545);
            Object objI2 = c0814p.I();
            if (objI2 == v) {
                objI2 = new com.quizlet.db.data.models.persisted.types.a(25);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a02 = (InterfaceC0773a0) L4.d(objArr2, null, (Function0) objI2, c0814p, 3072, 6);
            androidx.compose.material3.windowsizeclass.b bVarG = AbstractC3205m5.g(c0814p);
            Set set = androidx.compose.material3.windowsizeclass.c.b;
            int i5 = bVarG.a == 2 ? 5 : 2;
            int size = AbstractC3205m5.g(c0814p).a == 2 ? 5 : 4;
            float fA = AbstractC3223o5.a(c0814p, i5);
            m.g.t();
            float f = fA - j.k;
            int size2 = ((Boolean) interfaceC0773a0.getValue()).booleanValue() ? daily.size() : size;
            if (((Boolean) interfaceC0773a02.getValue()).booleanValue()) {
                size = weekly.size();
            }
            c0814p = c0814p;
            R4.a(nVar3, null, 0L, 0L, 0L, null, false, null, null, null, androidx.compose.runtime.internal.e.e(218846323, new G(f, i5, size2, size, interfaceC0773a0, interfaceC0773a02, function1, daily, weekly), c0814p), c0814p, (i4 >> 6) & 14, 1022);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new i(daily, weekly, nVar2, function1, i, 3);
        }
    }

    public static final io.reactivex.rxjava3.internal.operators.single.g b(p pVar, p other) {
        Intrinsics.checkNotNullParameter(pVar, "<this>");
        Intrinsics.checkNotNullParameter(other, "other");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = pVar.e(new com.quizlet.quizletandroid.ui.login.h(other, 6));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    public static com.bumptech.glide.manager.p c(int i, int i2, int i3, int i4) {
        return new com.bumptech.glide.manager.p(ImageReader.newInstance(i, i2, i3, i4));
    }

    public static final io.reactivex.rxjava3.internal.operators.single.g d(io.reactivex.rxjava3.internal.operators.single.g gVar, io.reactivex.rxjava3.internal.operators.single.g result, io.reactivex.rxjava3.internal.operators.flowable.b otherwise) {
        Intrinsics.checkNotNullParameter(gVar, "<this>");
        Intrinsics.checkNotNullParameter(result, "result");
        Intrinsics.checkNotNullParameter(otherwise, "otherwise");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = gVar.e(new com.quizlet.data.repository.searchexplanations.c(27, result, otherwise));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    public static final io.reactivex.rxjava3.internal.operators.single.g e(p pVar) {
        Intrinsics.checkNotNullParameter(pVar, "<this>");
        io.reactivex.rxjava3.internal.operators.single.g gVarG = pVar.g(com.quizlet.qutils.rx.a.c);
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        return gVarG;
    }

    public static final io.reactivex.rxjava3.internal.operators.single.g f(p pVar, p other) {
        Intrinsics.checkNotNullParameter(pVar, "<this>");
        Intrinsics.checkNotNullParameter(other, "other");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = pVar.e(new k(other, 12));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    /* JADX WARN: Removed duplicated region for block: B:53:0x00b7 A[Catch: all -> 0x00b3, PHI: r2
  0x00b7: PHI (r2v1 java.lang.Thread) = (r2v0 java.lang.Thread), (r2v11 java.lang.Thread) binds: [B:7:0x000c, B:47:0x00b0] A[DONT_GENERATE, DONT_INLINE], TRY_LEAVE, TryCatch #3 {, blocks: (B:4:0x0003, B:6:0x0007, B:8:0x000e, B:46:0x00ae, B:61:0x00e5, B:12:0x0023, B:52:0x00b6, B:53:0x00b7, B:64:0x00e9, B:65:0x00ea, B:13:0x0024, B:15:0x0031, B:25:0x004b, B:26:0x0052, B:28:0x005d, B:34:0x0072, B:35:0x0079, B:43:0x008a, B:44:0x00ac, B:18:0x0040, B:54:0x00b8, B:60:0x00e4, B:59:0x00c2), top: B:76:0x0003, inners: #2, #6 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static synchronized java.lang.ClassLoader g() {
        /*
            Method dump skipped, instructions count: 240
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.dynamite.d.g():java.lang.ClassLoader");
    }
}

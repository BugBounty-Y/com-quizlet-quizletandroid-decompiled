package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import android.content.res.Resources;
import android.graphics.Typeface;
import android.text.Spannable;
import android.text.SpannableStringBuilder;
import android.text.style.CharacterStyle;
import android.text.style.StyleSpan;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.n;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3161h6;
import com.quizlet.partskit.widgets.icon.InlineFontTypefaceSpan;
import com.quizlet.ui.compose.C4832z;
import java.io.File;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.h6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3161h6 {
    public AbstractC3161h6() {
        new ConcurrentHashMap();
    }

    public static final void a(final com.quizlet.features.infra.folder.menu.data.g item, androidx.compose.ui.n nVar, boolean z, final boolean z2, C4832z c4832z, final Function1 function1, InterfaceC0806l interfaceC0806l, final int i) {
        androidx.compose.ui.n nVar2;
        int i2;
        final boolean z3;
        C4832z c4832zG;
        final androidx.compose.ui.n nVar3;
        final C4832z c4832z2;
        Intrinsics.checkNotNullParameter(item, "item");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-288288047);
        int i3 = i | (c0814p.f(item) ? 4 : 2) | 432 | (c0814p.g(z2) ? 2048 : 1024) | 8192 | (c0814p.h(function1) ? 131072 : 65536);
        if ((74899 & i3) == 74898 && c0814p.x()) {
            c0814p.Q();
            nVar3 = nVar;
            z3 = z;
            c4832z2 = c4832z;
        } else {
            c0814p.S();
            int i4 = i & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i4 == 0 || c0814p.w()) {
                nVar2 = androidx.compose.ui.n.b;
                i2 = i3 & (-57345);
                z3 = true;
                c4832zG = AbstractC3170i6.g(c0814p);
            } else {
                c0814p.Q();
                nVar2 = nVar;
                c4832zG = c4832z;
                i2 = i3 & (-57345);
                z3 = z;
            }
            c0814p.q();
            long j = !z3 ? c4832zG.g : !z2 ? c4832zG.a : c4832zG.d;
            c0814p.X(2036591708);
            boolean z4 = ((458752 & i2) == 131072) | ((i2 & 14) == 4);
            Object objI = c0814p.I();
            if (z4 || objI == v) {
                objI = new com.quizlet.data.repository.explanations.exercise.a(18, function1, item);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            androidx.compose.ui.n nVar4 = nVar2;
            AbstractC3170i6.a(z2, z3, j, (Function0) objI, nVar4, androidx.compose.runtime.internal.e.e(1349813027, new com.quizlet.features.infra.folder.menu.composable.foldersubfolder.d(item, z2, c4832zG, z3), c0814p), c0814p, ((i2 >> 9) & 14) | 221232, 0);
            nVar3 = nVar4;
            c4832z2 = c4832zG;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2(nVar3, z3, z2, c4832z2, function1, i) { // from class: com.quizlet.features.infra.folder.menu.composable.foldersubfolder.c
                public final /* synthetic */ n b;
                public final /* synthetic */ boolean c;
                public final /* synthetic */ boolean d;
                public final /* synthetic */ C4832z e;
                public final /* synthetic */ Function1 f;

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(1);
                    com.quizlet.features.infra.folder.menu.data.g gVar = this.a;
                    C4832z c4832z3 = this.e;
                    Function1 function12 = this.f;
                    AbstractC3161h6.a(gVar, this.b, this.c, this.d, c4832z3, function12, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final void g(SpannableStringBuilder spannableStringBuilder, Context context, int i) {
        Intrinsics.checkNotNullParameter(spannableStringBuilder, "<this>");
        Intrinsics.checkNotNullParameter(context, "context");
        h(spannableStringBuilder, new InlineFontTypefaceSpan(androidx.core.content.res.k.a(context, i)));
    }

    public static final void h(Spannable spannable, CharacterStyle span) {
        Intrinsics.checkNotNullParameter(spannable, "<this>");
        Intrinsics.checkNotNullParameter(span, "span");
        spannable.setSpan(span, 0, spannable.length(), 33);
    }

    public static final void i(SpannableStringBuilder spannableStringBuilder, Context context, int i) {
        Intrinsics.checkNotNullParameter(spannableStringBuilder, "<this>");
        Intrinsics.checkNotNullParameter(context, "context");
        h(spannableStringBuilder, new StyleSpan(i));
    }

    public abstract Typeface b(Context context, androidx.core.content.res.e eVar, Resources resources, int i);

    public abstract Typeface c(Context context, androidx.core.provider.h[] hVarArr, int i);

    public Typeface d(Context context, List list, int i) {
        throw new IllegalStateException("createFromFontInfoWithFallback must only be called on API 29+");
    }

    public Typeface e(Context context, Resources resources, int i, String str, int i2) {
        File fileH = AbstractC3170i6.h(context);
        if (fileH == null) {
            return null;
        }
        try {
            if (AbstractC3170i6.e(fileH, resources, i)) {
                return Typeface.createFromFile(fileH.getPath());
            }
            return null;
        } catch (RuntimeException unused) {
            return null;
        } finally {
            fileH.delete();
        }
    }

    public androidx.core.provider.h f(androidx.core.provider.h[] hVarArr, int i) {
        new com.google.mlkit.common.internal.model.a(3);
        int i2 = (i & 1) == 0 ? 400 : 700;
        boolean z = (i & 2) != 0;
        androidx.core.provider.h hVar = null;
        int i3 = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        for (androidx.core.provider.h hVar2 : hVarArr) {
            int iAbs = (Math.abs(hVar2.c - i2) * 2) + (hVar2.d == z ? 0 : 1);
            if (hVar == null || i3 > iAbs) {
                hVar = hVar2;
                i3 = iAbs;
            }
        }
        return hVar;
    }
}

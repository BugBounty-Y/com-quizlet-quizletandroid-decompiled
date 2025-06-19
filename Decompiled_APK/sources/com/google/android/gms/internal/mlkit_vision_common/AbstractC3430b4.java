package com.google.android.gms.internal.mlkit_vision_common;

import android.animation.TimeInterpolator;
import android.content.Context;
import android.graphics.Path;
import android.util.TypedValue;
import android.view.animation.AnimationUtils;
import android.view.animation.Interpolator;
import android.view.animation.PathInterpolator;
import androidx.compose.runtime.C0814p;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3152g6;
import com.quizlet.features.universaluploadflow.data.C4452a;
import com.quizlet.features.universaluploadflow.data.C4453b;
import com.quizlet.features.universaluploadflow.data.C4454c;
import com.quizlet.features.universaluploadflow.data.C4455d;
import com.quizlet.features.universaluploadflow.data.InterfaceC4456e;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.b4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3430b4 {
    public static final com.quizlet.features.infra.basestudy.ui.models.a a(InterfaceC4456e interfaceC4456e, C0814p c0814p) {
        com.quizlet.features.infra.basestudy.ui.models.a aVar;
        com.quizlet.features.infra.basestudy.ui.models.a aVar2;
        Intrinsics.checkNotNullParameter(interfaceC4456e, "<this>");
        c0814p.X(-1679828438);
        if (interfaceC4456e instanceof C4453b) {
            c0814p.X(-1102544552);
            C4453b c4453b = (C4453b) interfaceC4456e;
            com.quizlet.data.model.m2 m2Var = com.quizlet.data.model.m2.c;
            com.quizlet.data.model.m2 m2Var2 = c4453b.a;
            if (m2Var2 != m2Var) {
                if (m2Var2 == com.quizlet.data.model.m2.a) {
                    throw new kotlin.n(null, 1, null);
                }
                if (m2Var2 == com.quizlet.data.model.m2.b) {
                    throw new kotlin.n(null, 1, null);
                }
                throw new NoWhenBranchMatchedException();
            }
            String strD = AbstractC3106b5.d(c0814p, R.string.uuf_generate_practice_test_error_title);
            String strD2 = AbstractC3106b5.d(c0814p, R.string.uuf_generate_practice_test_error_description);
            com.quizlet.themes.e.a(c0814p).d.getClass();
            aVar2 = new com.quizlet.features.infra.basestudy.ui.models.a(strD, strD2, androidx.compose.animation.core.J0.w(c0814p), AbstractC3106b5.d(c0814p, R.string.uuf_error_icon_description), AbstractC3106b5.d(c0814p, R.string.uuf_upload_page_button), c4453b.b);
            c0814p.p(false);
        } else {
            if (interfaceC4456e instanceof C4452a) {
                c0814p.X(-728280304);
                C4452a c4452a = (C4452a) interfaceC4456e;
                String strC = AbstractC3106b5.c(R.string.uuf_file_too_large_error, new Object[]{Integer.valueOf(c4452a.a)}, c0814p);
                com.quizlet.themes.e.a(c0814p).d.getClass();
                aVar = new com.quizlet.features.infra.basestudy.ui.models.a(strC, null, androidx.compose.animation.core.J0.w(c0814p), AbstractC3106b5.d(c0814p, R.string.uuf_error_icon_description), AbstractC3106b5.d(c0814p, R.string.uuf_upload_page_button), c4452a.b, 2);
                c0814p.p(false);
            } else if (interfaceC4456e instanceof C4454c) {
                c0814p.X(-728267715);
                String strD3 = AbstractC3106b5.d(c0814p, R.string.uuf_no_internet_error_title);
                String strD4 = AbstractC3106b5.d(c0814p, R.string.uuf_no_internet_error_description);
                com.quizlet.themes.e.a(c0814p).d.getClass();
                aVar = new com.quizlet.features.infra.basestudy.ui.models.a(strD3, strD4, androidx.compose.animation.core.J0.w(c0814p), AbstractC3106b5.d(c0814p, R.string.uuf_error_icon_description), AbstractC3106b5.d(c0814p, R.string.uuf_upload_page_button), ((C4454c) interfaceC4456e).a);
                c0814p.p(false);
            } else {
                if (!(interfaceC4456e instanceof C4455d)) {
                    throw com.google.android.gms.measurement.internal.Z.j(-728302724, c0814p, false);
                }
                c0814p.X(-1100992165);
                com.quizlet.data.model.m2 m2Var3 = com.quizlet.data.model.m2.c;
                com.quizlet.data.model.m2 m2Var4 = ((C4455d) interfaceC4456e).a;
                if (m2Var4 != m2Var3) {
                    if (m2Var4 == com.quizlet.data.model.m2.a) {
                        throw new kotlin.n(null, 1, null);
                    }
                    if (m2Var4 == com.quizlet.data.model.m2.b) {
                        throw new kotlin.n(null, 1, null);
                    }
                    throw new NoWhenBranchMatchedException();
                }
                String strD5 = AbstractC3106b5.d(c0814p, R.string.uuf_unavailable_error_title);
                String strD6 = AbstractC3106b5.d(c0814p, R.string.help_center);
                com.quizlet.themes.e.a(c0814p).d.getClass();
                aVar = new com.quizlet.features.infra.basestudy.ui.models.a(strD5, strD6, androidx.compose.animation.core.J0.w(c0814p), AbstractC3106b5.d(c0814p, R.string.uuf_error_icon_description), null, null, 48);
                c0814p.p(false);
            }
            aVar2 = aVar;
        }
        c0814p.p(false);
        return aVar2;
    }

    public static float b(String[] strArr, int i) throws NumberFormatException {
        float f = Float.parseFloat(strArr[i]);
        if (f >= DefinitionKt.NO_Float_VALUE && f <= 1.0f) {
            return f;
        }
        throw new IllegalArgumentException("Motion easing control point value must be between 0 and 1; instead got: " + f);
    }

    public static boolean c(String str, String str2) {
        return str.startsWith(str2.concat("(")) && str.endsWith(")");
    }

    public static int d(Context context, int i, int i2) {
        TypedValue typedValueB = AbstractC3436c4.b(context, i);
        return (typedValueB == null || typedValueB.type != 16) ? i2 : typedValueB.data;
    }

    public static TimeInterpolator e(Context context, int i, Interpolator interpolator) {
        TypedValue typedValue = new TypedValue();
        if (!context.getTheme().resolveAttribute(i, typedValue, true)) {
            return interpolator;
        }
        if (typedValue.type != 3) {
            throw new IllegalArgumentException("Motion easing theme attribute must be an @interpolator resource for ?attr/motionEasing*Interpolator attributes or a string for ?attr/motionEasing* attributes.");
        }
        String strValueOf = String.valueOf(typedValue.string);
        if (!c(strValueOf, "cubic-bezier") && !c(strValueOf, "path")) {
            return AnimationUtils.loadInterpolator(context, typedValue.resourceId);
        }
        if (c(strValueOf, "cubic-bezier")) {
            String[] strArrSplit = strValueOf.substring(13, strValueOf.length() - 1).split(",");
            if (strArrSplit.length == 4) {
                return new PathInterpolator(b(strArrSplit, 0), b(strArrSplit, 1), b(strArrSplit, 2), b(strArrSplit, 3));
            }
            throw new IllegalArgumentException("Motion easing theme attribute must have 4 control points if using bezier curve format; instead got: " + strArrSplit.length);
        }
        if (!c(strValueOf, "path")) {
            throw new IllegalArgumentException("Invalid motion easing type: ".concat(strValueOf));
        }
        String strSubstring = strValueOf.substring(5, strValueOf.length() - 1);
        Path path = new Path();
        try {
            androidx.core.graphics.g.b(AbstractC3152g6.d(strSubstring), path);
            return new PathInterpolator(path);
        } catch (RuntimeException e) {
            throw new RuntimeException("Error in parsing ".concat(strSubstring), e);
        }
    }
}

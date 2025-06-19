package com.google.android.gms.internal.mlkit_vision_barcode;

import android.graphics.drawable.Drawable;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0392j;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import com.quizlet.data.model.User;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.j6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3179j6 {
    public static final void a(com.quizlet.features.infra.folder.menu.data.b folder, kotlinx.collections.immutable.c selectedItems, Function1 onSubfolderSelected, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.q qVar2;
        Intrinsics.checkNotNullParameter(folder, "folder");
        Intrinsics.checkNotNullParameter(selectedItems, "selectedItems");
        Intrinsics.checkNotNullParameter(onSubfolderSelected, "onSubfolderSelected");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-789423194);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(folder) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(selectedItems) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(onSubfolderSelected) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            qVar2 = qVar;
            i2 |= c0814p.f(qVar2) ? 2048 : 1024;
        } else {
            qVar2 = qVar;
        }
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            int size = folder.d.size();
            C0380d c0380d = AbstractC0398m.a;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.u();
            float f = com.quizlet.ui.resources.designsystem.generated.j.g;
            C0392j c0392jG = AbstractC0398m.g(f);
            mVar.u();
            AbstractC0382e.b(size, qVar2, c0392jG, AbstractC0398m.g(f), 0, 0, null, androidx.compose.runtime.internal.e.e(-1685882897, new com.quizlet.features.home.composables.sections.b(folder, selectedItems, onSubfolderSelected, 1), c0814p), c0814p, ((i2 >> 6) & ContentType.LONG_FORM_ON_DEMAND) | 12582912, ContentType.LONG_FORM_ON_DEMAND);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.menu.i((Object) folder, (Object) selectedItems, (Object) onSubfolderSelected, qVar, i, 12);
        }
    }

    public static final int b(User user) {
        Intrinsics.checkNotNullParameter(user, "<this>");
        return c(Integer.valueOf(user.f));
    }

    public static final int c(Integer num) {
        return (num != null && num.intValue() == 3) ? R.string.plus_label : (num != null && num.intValue() == 1) ? R.string.plus_label : (num != null && num.intValue() == 2) ? R.string.teacher_label : R.string.empty;
    }

    public static void d(Drawable drawable, int i) {
        drawable.setTint(i);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static Drawable e(Drawable drawable) {
        if (!(drawable instanceof androidx.core.graphics.drawable.a)) {
            return drawable;
        }
        ((androidx.core.graphics.drawable.b) ((androidx.core.graphics.drawable.a) drawable)).getClass();
        return null;
    }
}

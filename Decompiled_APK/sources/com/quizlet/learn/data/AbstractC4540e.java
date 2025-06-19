package com.quizlet.learn.data;

import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.functions.Function0;

/* renamed from: com.quizlet.learn.data.e, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC4540e {
    public final int a;
    public final int b;
    public final boolean c;

    public AbstractC4540e(int i, int i2, Function0 function0, Function0 function02, boolean z) {
        this.a = i;
        this.b = i2;
        this.c = z;
    }

    public abstract Function0 a();

    public abstract Function0 b();

    public final androidx.compose.ui.graphics.painter.b c(InterfaceC0806l interfaceC0806l) {
        androidx.compose.ui.graphics.painter.b bVarD;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(1756446843);
        if (this.c) {
            c0814p.X(-1891506400);
            com.quizlet.ui.resources.icons.c cVar = (com.quizlet.ui.resources.icons.c) com.quizlet.themes.e.a(c0814p).d.b;
            com.quizlet.ui.resources.icons.c cVar2 = com.quizlet.ui.resources.icons.c.c;
            bVarD = cVar.A(c0814p);
            c0814p.p(false);
        } else {
            c0814p.X(-1891449205);
            com.quizlet.themes.e.a(c0814p).d.getClass();
            c0814p.X(-1253068804);
            bVarD = Z.d(R.drawable.ic_brand_trophy, c0814p, 0, false, false);
        }
        c0814p.p(false);
        return bVarD;
    }

    public abstract Integer d();

    public abstract Integer e();
}

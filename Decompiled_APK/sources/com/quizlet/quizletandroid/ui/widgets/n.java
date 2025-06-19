package com.quizlet.quizletandroid.ui.widgets;

import android.content.res.Resources;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3401v1;
import com.quizlet.data.model.C2;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class n implements kotlin.jvm.functions.c {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ C2 c;
    public final /* synthetic */ String d;

    public n(String str, boolean z, C2 c2) {
        this.d = str;
        this.b = z;
        this.c = c2;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) throws Resources.NotFoundException {
        switch (this.a) {
            case 0:
                androidx.glance.layout.r Row = (androidx.glance.layout.r) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(Row, "$this$Row");
                C0814p c0814p = (C0814p) ((InterfaceC0806l) obj2);
                ((com.quizlet.quizletandroid.ui.widgets.ui.theme.d) c0814p.j(com.quizlet.quizletandroid.ui.widgets.ui.theme.f.a)).getClass();
                AbstractC3401v1.a(this.d, null, com.quizlet.quizletandroid.ui.widgets.ui.theme.d.c(c0814p), 0, c0814p, 0, 10);
                c0814p.X(313228324);
                C2 c2 = this.c;
                if (this.b) {
                    com.quizlet.features.universaluploadflow.navigation.c.d(48, 0, c0814p, okhttp3.internal.platform.d.a(c2, c0814p), true);
                }
                c0814p.p(false);
                if (okhttp3.internal.platform.d.b(c2)) {
                    com.quizlet.features.universaluploadflow.navigation.c.a(c0814p, 0);
                }
                break;
            default:
                androidx.glance.layout.g Column = (androidx.glance.layout.g) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(Column, "$this$Column");
                C0814p c0814p2 = (C0814p) ((InterfaceC0806l) obj2);
                c0814p2.X(882256240);
                C2 c22 = this.c;
                boolean z = this.b;
                if (!z) {
                    String strC = org.slf4j.helpers.k.c(okhttp3.internal.platform.d.b(c22), c0814p2);
                    ((com.quizlet.quizletandroid.ui.widgets.ui.theme.d) c0814p2.j(com.quizlet.quizletandroid.ui.widgets.ui.theme.f.a)).getClass();
                    AbstractC3401v1.a(strC, null, com.quizlet.quizletandroid.ui.widgets.ui.theme.d.f(c0814p2), 0, c0814p2, 0, 10);
                    Column.getClass();
                    AbstractC3328d.c(new androidx.glance.layout.m(androidx.glance.unit.d.a), 0, 0, AbstractC4771d.a, c0814p2, 3072, 6);
                }
                c0814p2.p(false);
                AbstractC3328d.c(null, 0, 2, androidx.compose.runtime.internal.e.e(709241152, new n(this.d, z, c22), c0814p2), c0814p2, 3072, 3);
                if (!z) {
                    com.quizlet.features.universaluploadflow.navigation.c.d(0, 2, c0814p2, okhttp3.internal.platform.d.a(c22, c0814p2), false);
                }
                break;
        }
        return Unit.a;
    }

    public n(boolean z, C2 c2, String str) {
        this.b = z;
        this.c = c2;
        this.d = str;
    }
}

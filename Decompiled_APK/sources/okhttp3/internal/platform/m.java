package okhttp3.internal.platform;

import android.content.Context;
import android.content.Intent;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3180j7;
import com.google.android.gms.internal.mlkit_vision_barcode.M7;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3324c;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3332e;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3340g;
import com.quizlet.data.model.B2;
import com.quizlet.data.model.C2;
import com.quizlet.explanations.textbook.data.TextbookSetUpState;
import com.quizlet.explanations.textbook.ui.TextbookActivity;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.login.z;
import com.quizlet.quizletandroid.ui.widgets.t;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class m {
    public static final void a(C2 streakData, kotlinx.collections.immutable.b sets, androidx.appcompat.view.a linkProvider, androidx.glance.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.glance.n nVar2;
        Intrinsics.checkNotNullParameter(streakData, "streakData");
        Intrinsics.checkNotNullParameter(sets, "sets");
        Intrinsics.checkNotNullParameter(linkProvider, "linkProvider");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(528796584);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(streakData) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(sets) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= (i & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) == 0 ? c0814p.f(linkProvider) : c0814p.h(linkProvider) ? 256 : 128;
        }
        if (((i2 | 3072) & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.glance.n nVar3 = androidx.glance.n.a;
            AbstractC3328d.c(AbstractC3180j7.b(AbstractC3332e.d(nVar3), new androidx.glance.a(R.drawable.bg_widget)), 0, 0, androidx.compose.runtime.internal.e.e(-2067507004, new com.quizlet.assembly.compose.input.h(streakData, linkProvider, sets, 27), c0814p), c0814p, 3072, 6);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.globalnav.composable.d(streakData, sets, linkProvider, nVar2, i, 6);
        }
    }

    public static final void b(final B2 b2, final boolean z, final boolean z2, final androidx.appcompat.view.a aVar, InterfaceC0806l interfaceC0806l, final int i) {
        float f;
        float f2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(2020334989);
        if ((((c0814p.h(b2) ? 4 : 2) | i | (c0814p.g(z) ? 32 : 16) | (c0814p.g(z2) ? 256 : 128) | (c0814p.f(aVar) ? 2048 : 1024)) & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            Intrinsics.checkNotNullParameter(mVar, "<this>");
            float f3 = 12;
            Intrinsics.checkNotNullParameter(mVar, "<this>");
            if (z) {
                Intrinsics.checkNotNullParameter(mVar, "<this>");
                f = f3;
            } else {
                mVar.r();
                f = com.quizlet.ui.resources.designsystem.generated.j.e;
            }
            if (z2) {
                Intrinsics.checkNotNullParameter(mVar, "<this>");
                f2 = f3;
            } else {
                mVar.u();
                f2 = com.quizlet.ui.resources.designsystem.generated.j.g;
            }
            androidx.glance.layout.o oVar = new androidx.glance.layout.o(AbstractC3324c.h(f3), AbstractC3324c.h(f), AbstractC3324c.h(f3), AbstractC3324c.h(f2));
            c0814p.X(-2134169671);
            Object objI = c0814p.I();
            if (objI == C0804k.a) {
                objI = new z(22);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            M7.a(AbstractC3340g.c(oVar, (Function1) objI), null, androidx.compose.runtime.internal.e.e(-1080767889, new t(aVar, b2, 0), c0814p), c0814p, 384, 2);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2(z, z2, aVar, i) { // from class: com.quizlet.quizletandroid.ui.widgets.r
                public final /* synthetic */ boolean b;
                public final /* synthetic */ boolean c;
                public final /* synthetic */ androidx.appcompat.view.a d;

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(1);
                    androidx.appcompat.view.a aVar2 = this.d;
                    okhttp3.internal.platform.m.b(this.a, this.b, this.c, aVar2, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static Intent c(Context context, TextbookSetUpState state) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(state, "state");
        Intent intent = new Intent(context, (Class<?>) TextbookActivity.class);
        intent.putExtra("EXTRA_TEXTBOOK_STATE", state);
        return intent;
    }
}
